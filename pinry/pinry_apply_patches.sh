#!/usr/bin/env bash
# pinry_apply_patches.sh — apply the CCDC Pinry security patches (self-contained: patches embedded below)
#
#   sudo ./pinry_apply_patches.sh -n                 # dry run: show what each file's status is
#   sudo ./pinry_apply_patches.sh                    # patch code + nginx + local_settings, check, restart, health-check
#   sudo ./pinry_apply_patches.sh -t                 # ...and also wipe all API tokens + sessions (kicks red team out)
#   sudo ./pinry_apply_patches.sh -a 10.0.0.20       # allow pin-from-URL to this internal host (scoring engine)
#   sudo ./pinry_apply_patches.sh -R                 # keep public registration ON (if scoring needs sign-up)
#   sudo ./pinry_apply_patches.sh -u /root/pinry_patch_backup/<ts>   # ROLLBACK to a pre-patch backup
#
# Docker (getpinry/pinry) is auto-detected; for bare metal use -p /path/to/pinry (dir with manage.py).
# Every run backs up each file it touches first; any failed check/health test auto-rolls back.
set -uo pipefail

CONTAINER=""; APPDIR=""; DRY=0; RESET=0; KEEP_REG=0; ALLOW_HOSTS=""; ROLLBACK=""; NGINX_SITE="${NGINX_SITE:-}"
usage(){ sed -n '2,13p' "$0"; exit 0; }
while getopts "c:p:a:ntRu:h" o; do
  case $o in c) CONTAINER=$OPTARG;; p) APPDIR=${OPTARG%/};; a) ALLOW_HOSTS=$OPTARG;; n) DRY=1;; t) RESET=1;;
    R) KEEP_REG=1;; u) ROLLBACK=${OPTARG%/};; *) usage;; esac
done
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }

if [[ -t 1 ]]; then R=$'\e[1;31m' Y=$'\e[1;33m' G=$'\e[1;32m' C=$'\e[36m' N=$'\e[0m'; else R= Y= G= C= N=; fi
ok(){ echo "${G}[+]${N} $*"; }
warn(){ echo "${Y}[!]${N} $*"; }
err(){ echo "${R}[x]${N} $*"; }
info(){ echo "${C}[*]${N} $*"; }

WORK=$(mktemp -d /tmp/pinry_patch.XXXXXX); trap 'rm -rf "$WORK"' EXIT
printf -v TS '%(%Y%m%d_%H%M%S)T' -1

# ---------------- target abstraction (docker container or host) ----------------
MODE=""
detect(){
  if [[ -n $APPDIR ]]; then MODE=host; return; fi
  if [[ -z $CONTAINER ]] && command -v docker >/dev/null 2>&1; then
    CONTAINER=$(docker ps --format '{{.Names}} {{.Image}}' | grep -i pinry | head -1 | cut -d' ' -f1)
  fi
  if [[ -n $CONTAINER ]]; then
    MODE=docker
    if docker exec "$CONTAINER" test -f /pinry/manage.py 2>/dev/null; then APPDIR=/pinry
    else APPDIR=$(docker exec "$CONTAINER" sh -c 'dirname "$(find / -xdev -name manage.py -path "*pinry*" 2>/dev/null | head -1)"'); fi
    [[ -n $APPDIR && $APPDIR != . ]] || { err "can't find Pinry app dir in container $CONTAINER"; exit 1; }
    return
  fi
  APPDIR=$(find / -xdev \( -path /proc -o -path /sys -o -path /snap \) -prune -o -name manage.py -print 2>/dev/null \
            | while read -r m; do d=$(dirname "$m"); [[ -f $d/core/models.py && -d $d/pinry ]] && { echo "$d"; break; }; done)
  [[ -n $APPDIR ]] || { err "Pinry not found — use -c CONTAINER or -p /path/to/pinry"; exit 1; }
  MODE=host
}
t_exists(){ if [[ $MODE == docker ]]; then docker exec "$CONTAINER" test -f "$1"; else [[ -f $1 ]]; fi; }
t_get(){ if [[ $MODE == docker ]]; then docker cp "$CONTAINER:$1" "$2" >/dev/null 2>&1; else cp -p -- "$1" "$2"; fi; }
t_put(){ # src dest  (keeps dest owner/mode)
  if [[ $MODE == docker ]]; then
    docker cp "$1" "$CONTAINER:$2" >/dev/null && docker exec "$CONTAINER" chmod 644 "$2"
  else cat -- "$1" > "$2"; fi
}
t_sh(){ if [[ $MODE == docker ]]; then docker exec "$CONTAINER" sh -c "$1"; else sh -c "$1"; fi; }

# python that can import django (host mode); docker image has it on PATH
PY=python3
pick_py(){
  [[ $MODE == docker ]] && return
  local p cand
  for p in $(pgrep -f 'gunicorn|uwsgi|manage\.py' 2>/dev/null); do
    cand=$(readlink -f /proc/$p/exe 2>/dev/null); [[ $cand == *python* ]] && "$cand" -c 'import django' 2>/dev/null && { PY=$cand; return; }
  done
  for cand in "$APPDIR"/venv/bin/python "$APPDIR"/.venv/bin/python "$APPDIR"/../venv/bin/python python3; do
    "$cand" -c 'import django' 2>/dev/null && { PY=$cand; return; }
  done
  PY=""
}
settings_module(){
  if [[ $MODE == docker ]]; then echo pinry.settings.docker
  else local m; m=$(tr '\0' '\n' < /proc/"$(pgrep -f 'gunicorn|uwsgi' | head -1)"/environ 2>/dev/null | sed -n 's/^DJANGO_SETTINGS_MODULE=//p')
       echo "${m:-${DJANGO_SETTINGS_MODULE:-pinry.settings.docker}}"; fi
}
manage(){ t_sh "cd '$APPDIR' && ${PY:-python3} manage.py $* --settings=$(settings_module)"; }

# where local_settings lives (docker bootstrap copies /data/local_settings.py over the app copy at every start)
local_settings_paths(){
  if [[ $MODE == docker ]]; then echo /data/local_settings.py; echo "$APPDIR/pinry/settings/local_settings.py"
  else echo "$APPDIR/pinry/settings/local_settings.py"; fi
}
nginx_site(){
  [[ -n $NGINX_SITE ]] && { echo "$NGINX_SITE"; return; }
  if [[ $MODE == docker ]]; then echo /etc/nginx/sites-enabled/default; return; fi
  grep -lE 'proxy_pass http://(localhost|127\.0\.0\.1):8000|pinry' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | head -1
}

restart_app(){
  if [[ $MODE == docker ]]; then
    info "restarting container $CONTAINER"; docker restart "$CONTAINER" >/dev/null
  else
    local u; u=$(systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -iE 'pinry|gunicorn|uwsgi' | head -1)
    if [[ -n $u ]]; then info "restarting $u"; systemctl restart "$u"; else warn "no pinry/gunicorn systemd unit found — restart the app server yourself (or: pkill -HUP -f gunicorn)"; pkill -HUP -f gunicorn 2>/dev/null; fi
    command -v nginx >/dev/null && nginx -t 2>/dev/null && { systemctl reload nginx 2>/dev/null || nginx -s reload; }
  fi
}
health(){ # waits up to 60s: / must be 200, /api/v2/pins/ must not be 5xx
  local code='import sys,urllib.request,urllib.error
for p in ("/","/api/v2/pins/"):
    try: urllib.request.urlopen("http://127.0.0.1"+p,timeout=5)
    except urllib.error.HTTPError as e:
        if e.code>=500 or p=="/": print(p,e); sys.exit(1)
    except Exception as e: print(p,e); sys.exit(1)'
  local i
  for i in $(seq 1 20); do
    if [[ $MODE == docker ]]; then docker exec "$CONTAINER" python3 -c "$code" >/dev/null 2>&1 && return 0
    else python3 -c "$code" >/dev/null 2>&1 && return 0; fi
    sleep 3
  done
  [[ $MODE == docker ]] && docker exec "$CONTAINER" python3 -c "$code" || python3 -c "$code"
  return 1
}

# ---------------- rollback ----------------
do_rollback(){ # backupdir
  local bk=$1 tgt
  [[ -f $bk/targets ]] || { err "not a backup dir: $bk"; exit 1; }
  # shellcheck disable=SC1090
  source "$bk/meta"
  warn "rolling back from $bk ($MODE ${CONTAINER:-$APPDIR})"
  while IFS= read -r tgt; do
    [[ -f $bk/files$tgt ]] && t_put "$bk/files$tgt" "$tgt" && ok "restored $tgt"
  done < "$bk/targets"
  restart_app
  health && ok "app healthy after rollback" || err "app NOT healthy after rollback — check manually!"
}
if [[ -n $ROLLBACK ]]; then do_rollback "$ROLLBACK"; exit; fi

# ---------------- main ----------------
detect; pick_py
info "mode=$MODE ${CONTAINER:+container=$CONTAINER} app=$APPDIR"
sed -n '/^__PAYLOAD__$/,$p' "$0" | tail -n +2 | base64 -d | tar xz -C "$WORK" || { err "payload corrupt"; exit 1; }

BK=/root/pinry_patch_backup/${TS}_$$
((DRY)) || { mkdir -p "$BK/files"; chmod 700 /root/pinry_patch_backup "$BK";
  printf 'MODE=%q\nCONTAINER=%q\nAPPDIR=%q\nNGINX_SITE=%q\n' "$MODE" "$CONTAINER" "$APPDIR" "$(nginx_site)" > "$BK/meta"; }
backup_file(){ local t=$1; ((DRY)) && return; mkdir -p "$BK/files$(dirname "$t")"; t_get "$t" "$BK/files$t" && echo "$t" >> "$BK/targets"; }

PATCHED=0; SKIPPED=0; FAILED=0
# MANIFEST: rel orig_sha new_sha
while read -r rel osha nsha; do
  if [[ $rel == docker/nginx/sites-enabled/default ]]; then tgt=$(nginx_site); [[ -n $tgt ]] || { warn "nginx site config not found — skipping nginx (set NGINX_SITE=/path)"; continue; }
  else tgt=$APPDIR/$rel; fi
  t_exists "$tgt" || { warn "missing on target: $tgt — skipped"; SKIPPED=$((SKIPPED+1)); continue; }
  cur=$WORK/cur_${rel//\//_}; t_get "$tgt" "$cur"
  csha=$(sha256sum "$cur" | cut -d' ' -f1)
  if [[ $csha == "$nsha" ]] || { command -v patch >/dev/null && patch -s -R --dry-run -F3 -r - -o /dev/null "$cur" < "$WORK/patches/$rel.patch" >/dev/null 2>&1; }; then
    ok "already patched: $tgt"; SKIPPED=$((SKIPPED+1)); continue; fi
  out=$WORK/out_${rel//\//_}
  if [[ $csha == "$osha" ]]; then cp "$WORK/new/$rel" "$out"; how="exact upstream match"
  elif command -v patch >/dev/null && patch -s -F3 --no-backup-if-mismatch -r - -o "$out" "$cur" < "$WORK/patches/$rel.patch" >/dev/null 2>&1; then
    how="fuzzy (file differs from upstream — diff it! version drift or TAMPERING)"
  else
    err "CANNOT patch $tgt — differs from upstream master (other version or tampered). Compare: diff with pinry_ccdc.patch hunks"; FAILED=$((FAILED+1)); continue
  fi
  if ((DRY)); then info "would patch: $tgt [$how]"; continue; fi
  backup_file "$tgt"; t_put "$out" "$tgt" && { ok "patched: $tgt [$how]"; PATCHED=$((PATCHED+1)); } || { err "write failed: $tgt"; FAILED=$((FAILED+1)); }
done < "$WORK/MANIFEST"

# ---- local_settings hardening block (idempotent: replaces previous CCDC block)
KEY=$(head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | cut -c1-60)
hosts_py=""; IFS=',' read -ra H <<<"$ALLOW_HOSTS"; for h in "${H[@]}"; do [[ -n $h ]] && hosts_py+="'$h', "; done
for ls in $(local_settings_paths); do
  if ! t_exists "$ls"; then [[ $ls == /data/* ]] && warn "$ls missing"; continue; fi
  if ((DRY)); then info "would add CCDC block to $ls (new SECRET_KEY, registrations $( ((KEEP_REG)) && echo ON || echo OFF))"; continue; fi
  backup_file "$ls"
  f=$WORK/ls.py; t_get "$ls" "$f"
  sed -i '/^# ---- CCDC hardening BEGIN/,/^# ---- CCDC hardening END/d' "$f"
  cat >> "$f" <<EOF
# ---- CCDC hardening BEGIN ($TS) ----
SECRET_KEY = "$KEY"
DEBUG = False
ALLOW_NEW_REGISTRATIONS = $( ((KEEP_REG)) && echo True || echo False )
PIN_FETCH_ALLOW_HOSTS = [${hosts_py%, }]
# ---- CCDC hardening END ----
EOF
  t_put "$f" "$ls" && ok "hardened settings: $ls (SECRET_KEY rotated -> all sessions invalidated)"
done

((DRY)) && { info "dry run done — nothing changed"; exit 0; }
((FAILED)) && warn "$FAILED file(s) could not be patched (see above) — the rest were applied"

# ---- validate before restart; roll back on failure
if [[ $MODE == host && -z $PY ]]; then warn "no python with django found — skipping 'manage.py check'"
else
  info "running manage.py check"
  if ! manage check >"$WORK/check.log" 2>&1; then
    err "Django check FAILED:"; tail -15 "$WORK/check.log"; do_rollback "$BK"; exit 1
  fi
  ok "Django check passed"
fi
[[ $MODE == docker ]] && { docker exec "$CONTAINER" nginx -t >/dev/null 2>&1 || { err "nginx -t failed"; docker exec "$CONTAINER" nginx -t; do_rollback "$BK"; exit 1; }; }
[[ $MODE == host ]] && command -v nginx >/dev/null && { nginx -t >/dev/null 2>&1 || { err "nginx -t failed"; do_rollback "$BK"; exit 1; }; }

restart_app
if health; then ok "app healthy (/ OK, API not erroring)"
else err "health check FAILED after patch — rolling back"; do_rollback "$BK"; exit 1; fi

if ((RESET)); then
  manage users_reset_tokens >/dev/null 2>&1 && ok "all API tokens wiped" || warn "token reset failed"
  manage shell -c "'from django.contrib.sessions.models import Session; print(Session.objects.all().delete())'" >/dev/null 2>&1 \
    && ok "all sessions deleted" || warn "session wipe failed"
  warn "now change every user's password (manage.py changepassword <user>)"
fi
ok "done: $PATCHED patched, $SKIPPED skipped, $FAILED failed. Backup/rollback: sudo $0 -u $BK"
exit 0
__PAYLOAD__
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
GAEA
