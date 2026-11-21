#!/usr/bin/env bash
# pinry_backup_bm.sh — backup / restore for a bare-metal (no Docker) Pinry install
#
#   sudo ./pinry_backup_bm.sh                      # backup now (app /pinry, data /data)
#   sudo ./pinry_backup_bm.sh -a /pinry -d /data   # explicit paths
#   sudo ./pinry_backup_bm.sh -i 900 -k 8          # every 15 min, keep newest 8
#   sudo ./pinry_backup_bm.sh -o /mnt/other        # also copy each backup to a 2nd location (recommended)
#   sudo ./pinry_backup_bm.sh -l                   # list backups
#   sudo ./pinry_backup_bm.sh -r <backup-dir>      # RESTORE app code + data + nginx
#   sudo ./pinry_backup_bm.sh -r <backup-dir> -D   # restore data only (db, media, settings)
#
# Each backup: consistent SQLite copy (online backup API) or pg_dumpall, app tarball, data tarball
# (db excluded — it's copied separately), /etc/nginx, systemd/supervisor units that start Pinry,
# root's crontab, and SHA256SUMS. Read-only on the live system unless you restore.
set -uo pipefail

APP=/pinry; DATA=/data; ROOT=/root/pinry_backups; INTERVAL=0; KEEP=10; OFFBOX=""; RESTORE=""; DATA_ONLY=0; YES=0; LIST=0
usage(){ sed -n '2,14p' "$0"; echo "Other: -b BACKUP_ROOT (default $ROOT)  -y (skip restore prompt)"; exit 0; }
while getopts "a:d:b:i:k:o:r:Dlyh" o; do
  case $o in a) APP=${OPTARG%/};; d) DATA=${OPTARG%/};; b) ROOT=${OPTARG%/};; i) INTERVAL=$OPTARG;; k) KEEP=$OPTARG;;
    o) OFFBOX=${OPTARG%/};; r) RESTORE=${OPTARG%/};; D) DATA_ONLY=1;; l) LIST=1;; y) YES=1;; *) usage;; esac
done
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }

if [[ -t 1 ]]; then R=$'\e[1;31m' Y=$'\e[1;33m' G=$'\e[1;32m' C=$'\e[36m' N=$'\e[0m'; else R= Y= G= C= N=; fi
ok(){ echo "${G}[+]${N} $*"; }
warn(){ echo "${Y}[!]${N} $*"; }
err(){ echo "${R}[x]${N} $*"; }
info(){ echo "${C}[*]${N} $*"; }
die(){ err "$*"; exit 1; }

mkdir -p "$ROOT" && chmod 700 "$ROOT"

if ((LIST)); then
  for d in $(ls -1d "$ROOT"/2*/ 2>/dev/null | sort); do
    printf '%s  %6s  %s\n' "$(basename "$d")" "$(du -sh "$d" | cut -f1)" "$(cat "$d/STATUS" 2>/dev/null)"
  done
  exit 0
fi

# ---------------------------------------------------------------- sanity + discovery
[[ -d $APP ]] || die "app folder not found: $APP (use -a /path/to/pinry)"
[[ -f $APP/manage.py ]] || die "$APP has no manage.py — not a Pinry base folder"
[[ -d $DATA ]] || { warn "data folder $DATA not found — backing up app only (use -d if data lives elsewhere)"; DATA=""; }

# find the settings files without running any Pinry code
SETTINGS_FILES=("$APP"/pinry/settings/*.py)
[[ -n $DATA && -f $DATA/local_settings.py ]] && SETTINGS_FILES+=("$DATA/local_settings.py")
DB_ENGINE=$(grep -hoE "django\.db\.backends\.[a-z0-9_]+" "${SETTINGS_FILES[@]}" 2>/dev/null | tail -1)
DB_FILE=""
if [[ $DB_ENGINE == *sqlite3* ]]; then
  DB_FILE=$(grep -hA4 "sqlite3" "${SETTINGS_FILES[@]}" 2>/dev/null | grep -oE "'NAME'\s*:\s*'[^']+'|\"NAME\"\s*:\s*\"[^\"]+\"" | tail -1 | sed -E "s/.*:\s*['\"]([^'\"]+)['\"]/\1/")
fi
[[ -z $DB_FILE && -n $DATA && -f $DATA/production.db ]] && DB_FILE=$DATA/production.db

units(){ # systemd / supervisor / init files that mention pinry or its gunicorn
  grep -rlEi 'pinry|gunicorn' /etc/systemd/system /lib/systemd/system /etc/supervisor /etc/init.d /etc/rc.local 2>/dev/null \
    | grep -vE '\.wants/' | head -20
}

# ---------------------------------------------------------------- backup
NOPRUNE=0
backup_once(){
  local ts d
  printf -v ts '%(%Y%m%d_%H%M%S)T' -1
  d=$ROOT/$ts; mkdir -p "$d"; chmod 700 "$d"
  info "backing up $APP ${DATA:+and $DATA} -> $d"
  printf 'APP=%q\nDATA=%q\nDB_FILE=%q\nDB_ENGINE=%q\n' "$APP" "$DATA" "$DB_FILE" "$DB_ENGINE" > "$d/meta"

  # database
  if [[ -n $DB_FILE && -f $DB_FILE ]]; then
    if python3 -c "import sqlite3,sys;s=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True);d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close()" "$DB_FILE" "$d/production.db" 2>/dev/null; then
      ok "sqlite db $DB_FILE (online backup, $(du -h "$d/production.db" | cut -f1))"
    else
      warn "online sqlite backup failed — plain copy"; cp -p "$DB_FILE" "$d/production.db"
    fi
  elif [[ $DB_ENGINE == *postgres* ]]; then
    if sudo -u postgres pg_dumpall > "$d/pg_dumpall.sql" 2>/dev/null; then ok "postgres pg_dumpall ($(du -h "$d/pg_dumpall.sql" | cut -f1))"
    else warn "pg_dumpall failed — dump the DB manually"; rm -f "$d/pg_dumpall.sql"; fi
  else
    warn "database not found (engine: ${DB_ENGINE:-unknown}) — not captured separately"
  fi

  # app code (all of it — compare later to spot tampering)
  tar czpf "$d/app.tgz" -C / "${APP#/}" 2>/dev/null && ok "app code $APP ($(du -h "$d/app.tgz" | cut -f1))" || err "app tarball failed"

  # data folder minus the live db (captured consistently above)
  if [[ -n $DATA ]]; then
    local ex=()
    [[ -n $DB_FILE && $DB_FILE == "$DATA"/* ]] && ex=(--exclude="${DB_FILE#/}" --exclude="${DB_FILE#/}-journal" --exclude="${DB_FILE#/}-wal")
    tar czpf "$d/data.tgz" -C / "${ex[@]}" --exclude="${DATA#/}/.pre_restore_*" "${DATA#/}" 2>/dev/null \
      && ok "data $DATA (media, settings, logs) ($(du -h "$d/data.tgz" | cut -f1))" || err "data tarball failed"
  fi

  [[ -d /etc/nginx ]] && tar czpf "$d/nginx.tgz" -C / etc/nginx 2>/dev/null && ok "/etc/nginx"
  mapfile -t U < <(units)
  if ((${#U[@]})); then tar czpf "$d/units.tgz" -C / "${U[@]#/}" 2>/dev/null && ok "startup files: ${U[*]}"; fi
  if crontab -l > "$d/root.crontab" 2>/dev/null; then ok "root crontab"; else rm -f "$d/root.crontab"; fi

  (cd "$d" && sha256sum ./* > SHA256SUMS 2>/dev/null)
  echo "ok $(date '+%F %T') app=$APP data=${DATA:-none}" > "$d/STATUS"
  if [[ -n $OFFBOX ]]; then mkdir -p "$OFFBOX" && cp -a "$d" "$OFFBOX/" && ok "copied to $OFFBOX/$ts" || err "copy to $OFFBOX failed"; fi
  ((NOPRUNE)) || prune
  ok "backup complete: $d"
  LAST_BACKUP=$d
}

prune(){
  local dirs; mapfile -t dirs < <(ls -1d "$ROOT"/2*/ 2>/dev/null | sort)
  while (( ${#dirs[@]} > KEEP )); do
    rm -rf -- "${dirs[0]%/}"; info "pruned $(basename "${dirs[0]%/}")"; dirs=("${dirs[@]:1}")
  done
}

# ---------------------------------------------------------------- restore
reload_app(){
  local u; u=$(systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -iE 'pinry|gunicorn|uwsgi' | head -1)
  if [[ -n $u ]]; then systemctl restart "$u" && info "restarted $u"
  elif pgrep -f gunicorn >/dev/null; then pkill -HUP -of gunicorn && info "sent HUP to gunicorn master (workers reload code)"
  else warn "no gunicorn/systemd unit found — restart Pinry yourself"; fi
  command -v nginx >/dev/null && nginx -t >/dev/null 2>&1 && nginx -s reload 2>/dev/null
}
healthy(){
  local i
  for i in $(seq 1 15); do
    python3 -c 'import urllib.request;urllib.request.urlopen("http://127.0.0.1/",timeout=5)' 2>/dev/null && return 0; sleep 2
  done; return 1
}

restore(){
  local b=$1 ts
  [[ -f $b/STATUS ]] || die "not a backup dir: $b"
  # shellcheck disable=SC1091
  source "$b/meta"
  if [[ -f $b/SHA256SUMS ]]; then (cd "$b" && sha256sum --quiet -c SHA256SUMS 2>/dev/null) && ok "backup checksums verified" \
    || { err "CHECKSUM MISMATCH — backup may be tampered"; ((YES)) || exit 1; }; fi
  if ((! YES)); then
    read -r -p "Restore $(basename "$b") ($( ((DATA_ONLY)) && echo 'data only' || echo 'app + data + nginx'))? type YES: " a
    [[ $a == YES ]] || { echo aborted; exit 1; }
  fi
  info "safety backup of the CURRENT state first (evidence + undo)"
  NOPRUNE=1 backup_once
  printf -v ts '%(%Y%m%d_%H%M%S)T' -1

  if [[ -n $DATA && -f $b/data.tgz ]]; then
    local aside=$DATA/.pre_restore_$ts x
    mkdir -p "$aside" && chmod 700 "$aside"
    for x in "${DB_FILE#$DATA/}" local_settings.py static/media nginx-access.log nginx-error.log; do
      [[ -n $x && -e $DATA/$x ]] && mkdir -p "$aside/$(dirname "$x")" && mv "$DATA/$x" "$aside/$x"
    done
    tar xzpf "$b/data.tgz" -C / && ok "restored $DATA (current files moved to $aside)" || err "data restore failed"
    [[ -f $b/production.db && -n $DB_FILE ]] && cp -p "$b/production.db" "$DB_FILE" && ok "restored database $DB_FILE"
    chown -R www-data:www-data "$DATA" 2>/dev/null
  fi
  [[ -f $b/pg_dumpall.sql ]] && warn "postgres dump present — restore manually: sudo -u postgres psql < $b/pg_dumpall.sql"

  if ((! DATA_ONLY)); then
    if [[ -f $b/app.tgz ]]; then
      rm -rf "${APP}.pre_restore_$ts"; mv "$APP" "${APP}.pre_restore_$ts" \
        && tar xzpf "$b/app.tgz" -C / && ok "restored $APP (old code kept at ${APP}.pre_restore_$ts for forensics)" \
        || { err "app restore failed — putting old code back"; [[ -d $APP ]] || mv "${APP}.pre_restore_$ts" "$APP"; }
      chmod 700 "${APP}.pre_restore_$ts" 2>/dev/null
    fi
    if [[ -f $b/nginx.tgz ]]; then
      cp -a /etc/nginx "/root/nginx.pre_restore_$ts" && tar xzpf "$b/nginx.tgz" -C / \
        && { nginx -t >/dev/null 2>&1 && ok "restored /etc/nginx" || { err "restored nginx config fails nginx -t — reverting"; rm -rf /etc/nginx; cp -a "/root/nginx.pre_restore_$ts" /etc/nginx; }; }
    fi
  fi
  reload_app
  healthy && ok "Pinry responds on http://127.0.0.1/" || err "Pinry not responding — check the app server"
}

# ---------------------------------------------------------------- main
info "app=$APP data=${DATA:-none} db=${DB_FILE:-${DB_ENGINE:-?}}"
if [[ -n $RESTORE ]]; then restore "$RESTORE"; exit; fi
while :; do
  backup_once
  ((INTERVAL > 0)) || break
  sleep "$INTERVAL"
done
