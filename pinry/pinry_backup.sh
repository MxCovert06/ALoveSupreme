#!/usr/bin/env bash
# pinry_backup.sh — snapshot + restore a Dockerized Pinry (getpinry/pinry) for CCDC
#
#   sudo ./pinry_backup.sh                    # take a backup now
#   sudo ./pinry_backup.sh -i 900 -k 8        # backup every 15 min, keep newest 8 (run under systemd-run/tmux)
#   sudo ./pinry_backup.sh -o /mnt/usb        # also copy each backup to a second location (do this! red team can rm /root)
#   sudo ./pinry_backup.sh -l                 # list backups
#   sudo ./pinry_backup.sh -r <backup-dir>    # RESTORE db + media + settings + app code + nginx into the container
#   sudo ./pinry_backup.sh -r <dir> -d        # restore data only (db/media/settings), leave code alone
#
# Each backup holds: consistent SQLite copy (or pg_dumpall), /data tarball, app code (/pinry), /etc/nginx,
# a `docker commit` image snapshot, docker inspect JSON, and recreate.sh to rebuild the container from scratch.
set -uo pipefail

CONTAINER=""; ROOT=/root/pinry_backups; INTERVAL=0; KEEP=10; OFFBOX=""; RESTORE=""; DATA_ONLY=0; YES=0; LIST=0
usage(){ sed -n '2,13p' "$0"; echo "Other: -c CONTAINER  -b BACKUP_ROOT (default $ROOT)  -y (no restore prompt)"; exit 0; }
while getopts "c:b:i:k:o:r:dlyh" o; do
  case $o in c) CONTAINER=$OPTARG;; b) ROOT=${OPTARG%/};; i) INTERVAL=$OPTARG;; k) KEEP=$OPTARG;; o) OFFBOX=${OPTARG%/};;
    r) RESTORE=${OPTARG%/};; d) DATA_ONLY=1;; l) LIST=1;; y) YES=1;; *) usage;; esac
done
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
command -v docker >/dev/null || { echo "docker not found"; exit 1; }

if [[ -t 1 ]]; then R=$'\e[1;31m' Y=$'\e[1;33m' G=$'\e[1;32m' C=$'\e[36m' N=$'\e[0m'; else R= Y= G= C= N=; fi
ok(){ echo "${G}[+]${N} $*"; }
warn(){ echo "${Y}[!]${N} $*"; }
err(){ echo "${R}[x]${N} $*"; }
info(){ echo "${C}[*]${N} $*"; }

mkdir -p "$ROOT" && chmod 700 "$ROOT"

if ((LIST)); then
  for d in $(ls -1d "$ROOT"/*/ 2>/dev/null | sort); do
    printf '%s  %6s  %s\n' "$(basename "$d")" "$(du -sh "$d" | cut -f1)" "$(cat "$d/STATUS" 2>/dev/null)"
  done
  exit 0
fi

find_container(){
  [[ -n $CONTAINER ]] && return
  CONTAINER=$(docker ps -a --format '{{.Names}} {{.Image}}' | grep -i pinry | grep -v 'pinry-ccdc-backup' | head -1 | cut -d' ' -f1)
  [[ -n $CONTAINER ]] || { err "no pinry container found — use -c NAME"; exit 1; }
}
running(){ [[ $(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null) == true ]]; }
APP=/pinry
NOPRUNE=0

# ------------------------------------------------------------------ backup
backup_once(){
  local ts d tmp
  printf -v ts '%(%Y%m%d_%H%M%S)T' -1
  d=$ROOT/$ts; mkdir -p "$d"; chmod 700 "$d"
  info "backing up container '$CONTAINER' -> $d"
  docker inspect "$CONTAINER" > "$d/inspect.json"

  if running; then
    # consistent DB copy while the app is live
    if docker exec "$CONTAINER" test -f /data/production.db; then
      if docker exec "$CONTAINER" python3 -c "import sqlite3;s=sqlite3.connect('/data/production.db');d=sqlite3.connect('/tmp/ccdc_db_backup.db');s.backup(d);d.close()" 2>/dev/null \
         && docker cp "$CONTAINER:/tmp/ccdc_db_backup.db" "$d/production.db" >/dev/null; then
        docker exec "$CONTAINER" rm -f /tmp/ccdc_db_backup.db; ok "sqlite db (online backup API)"
      else warn "sqlite online backup failed — falling back to file copy"; docker cp "$CONTAINER:/data/production.db" "$d/production.db" >/dev/null; fi
    else
      local db; db=$(docker ps --format '{{.Names}} {{.Image}}' | grep -iE 'postgres|db' | grep -vi pinry | head -1 | cut -d' ' -f1)
      if [[ -n $db ]]; then docker exec "$db" pg_dumpall -U postgres > "$d/pg_dumpall.sql" 2>/dev/null && ok "postgres dump from $db" || warn "pg_dumpall failed on $db"
      else warn "no /data/production.db and no postgres container — DB not captured separately"; fi
    fi
  else warn "container not running — copying files as-is"; fi

  docker cp "$CONTAINER:/data" - 2>/dev/null | gzip -1 > "$d/data.tar.gz" && ok "/data ($(du -h "$d/data.tar.gz" | cut -f1))" || err "/data copy failed"
  docker cp "$CONTAINER:$APP" - 2>/dev/null | gzip -1 > "$d/app.tar.gz" && ok "app code $APP ($(du -h "$d/app.tar.gz" | cut -f1))" || err "app copy failed"
  docker cp "$CONTAINER:/etc/nginx" - 2>/dev/null | gzip -1 > "$d/nginx.tar.gz" && ok "/etc/nginx" || warn "nginx copy failed"

  if docker commit --pause=false "$CONTAINER" "pinry-ccdc-backup:$ts" >/dev/null 2>&1; then ok "image snapshot pinry-ccdc-backup:$ts"; echo "pinry-ccdc-backup:$ts" > "$d/IMAGE"
  else warn "docker commit failed"; fi

  write_recreate "$d" "$ts"
  (cd "$d" && sha256sum ./* > SHA256SUMS 2>/dev/null)
  echo "ok $(date '+%F %T') container=$CONTAINER" > "$d/STATUS"
  if [[ -n $OFFBOX ]]; then mkdir -p "$OFFBOX" && cp -a "$d" "$OFFBOX/" && ok "copied to $OFFBOX/$ts" || err "off-box copy to $OFFBOX failed"; fi
  ((NOPRUNE)) || prune
  ok "backup complete: $d"
}

write_recreate(){ # dir ts — build a docker run command from inspect so the container can be rebuilt if deleted
  local d=$1 ts=$2 f=$1/recreate.sh name img rp net line
  name=$(docker inspect -f '{{.Name}}' "$CONTAINER" | sed 's#^/##')
  img=$(cat "$d/IMAGE" 2>/dev/null || docker inspect -f '{{.Config.Image}}' "$CONTAINER")
  rp=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$CONTAINER")
  net=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$CONTAINER")
  {
    echo '#!/usr/bin/env bash'
    echo "# Recreate '$name' from backup $ts. Default image = the committed snapshot; pass another image as \$1."
    echo "# After it starts, restore data with: pinry_backup.sh -r $d -d"
    echo 'set -e'
    printf 'IMG=${1:-%q}\n' "$img"
    printf 'docker rm -f %q 2>/dev/null || true\n' "$name"
    printf 'docker run -d --name %q' "$name"
    [[ -n $rp && $rp != no ]] && printf ' --restart %q' "$rp"
    [[ -n $net && $net != default && $net != bridge ]] && printf ' --network %q' "$net"
    while IFS='|' read -r ip hp cp; do
      [[ -z ${cp:-} ]] && continue
      if [[ -n $ip ]]; then printf ' -p %q' "$ip:$hp:$cp"; else printf ' -p %q' "$hp:$cp"; fi
    done < <(docker inspect -f '{{range $p,$b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}}|{{.HostPort}}|{{$p}}{{"\n"}}{{end}}{{end}}' "$CONTAINER")
    while read -r typ src dst vname; do
      [[ -z ${dst:-} ]] && continue
      if [[ $typ == volume ]]; then printf ' -v %q' "$vname:$dst"; else printf ' -v %q' "$src:$dst"; fi
    done < <(docker inspect -f '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}} {{.Name}}{{"\n"}}{{end}}' "$CONTAINER")
    while IFS= read -r line; do
      [[ -z $line || $line == PATH=* || $line == LANG=* || $line == GPG_KEY=* || $line == PYTHON_* ]] && continue
      printf ' -e %q' "$line"
    done < <(docker inspect -f '{{range .Config.Env}}{{.}}{{"\n"}}{{end}}' "$CONTAINER")
    echo ' "$IMG"'
  } > "$f"
  chmod 700 "$f"
}

prune(){
  local dirs n
  mapfile -t dirs < <(ls -1d "$ROOT"/2*/ 2>/dev/null | sort)
  n=${#dirs[@]}
  while (( n > KEEP )); do
    local old=${dirs[0]%/}; local img; img=$(cat "$old/IMAGE" 2>/dev/null)
    [[ -n $img ]] && docker rmi "$img" >/dev/null 2>&1
    rm -rf -- "$old"; info "pruned old backup $(basename "$old")"
    dirs=("${dirs[@]:1}"); n=${#dirs[@]}
  done
}

# ------------------------------------------------------------------ restore
restore(){
  local d=$1 ts
  [[ -f $d/data.tar.gz ]] || { err "not a backup dir: $d"; exit 1; }
  if [[ -f $d/SHA256SUMS ]]; then (cd "$d" && sha256sum --quiet -c SHA256SUMS 2>/dev/null) && ok "backup checksums verified" \
      || { err "CHECKSUM MISMATCH — backup may have been tampered with"; ((YES)) || exit 1; }; fi
  docker inspect "$CONTAINER" >/dev/null 2>&1 || { err "container $CONTAINER is gone — run $d/recreate.sh first, then restore with -d"; exit 1; }
  if ((! YES)); then
    read -r -p "Restore $(basename "$d") into '$CONTAINER' ($( ((DATA_ONLY)) && echo 'data only' || echo 'data + code + nginx'))? type YES: " a
    [[ $a == YES ]] || { echo aborted; exit 1; }
  fi
  info "taking a safety backup of the CURRENT state first (evidence + undo)"
  NOPRUNE=1 backup_once
  running || docker start "$CONTAINER" >/dev/null

  printf -v ts '%(%Y%m%d_%H%M%S)T' -1
  # move current data aside (inside the volume, outside the web-served /data/static), then restore
  docker exec "$CONTAINER" sh -c "mkdir -p /data/.pre_restore_$ts && chmod 700 /data/.pre_restore_$ts &&
    for x in production.db local_settings.py static/media nginx-access.log nginx-error.log; do [ -e /data/\$x ] && mkdir -p /data/.pre_restore_$ts/\$(dirname \$x) && mv /data/\$x /data/.pre_restore_$ts/\$x; done; true"
  gunzip -c "$d/data.tar.gz" | docker cp - "$CONTAINER:/" && ok "restored /data (db, media, local_settings)" || err "/data restore failed"
  if [[ -f $d/production.db ]]; then docker cp "$d/production.db" "$CONTAINER:/data/production.db" >/dev/null && ok "restored consistent DB copy"; fi
  if [[ -f $d/pg_dumpall.sql ]]; then warn "postgres dump present: restore manually: docker exec -i <db> psql -U postgres < $d/pg_dumpall.sql"; fi

  if ((! DATA_ONLY)); then
    docker exec "$CONTAINER" sh -c "rm -rf ${APP}.ccdc_old && mv $APP ${APP}.ccdc_old" \
      && gunzip -c "$d/app.tar.gz" | docker cp - "$CONTAINER:$(dirname $APP)" && ok "restored app code (previous code kept at ${APP}.ccdc_old for forensics)" \
      || { err "code restore failed — putting old code back"; docker exec "$CONTAINER" sh -c "[ -d $APP ] || mv ${APP}.ccdc_old $APP"; }
    if [[ -f $d/nginx.tar.gz ]]; then gunzip -c "$d/nginx.tar.gz" | docker cp - "$CONTAINER:/etc" && ok "restored /etc/nginx"; fi
  fi
  docker exec "$CONTAINER" chown -R www-data:www-data /data 2>/dev/null
  docker restart "$CONTAINER" >/dev/null && info "container restarted, checking health..."
  local i code='import urllib.request;urllib.request.urlopen("http://127.0.0.1/",timeout=5)'
  for i in $(seq 1 20); do docker exec "$CONTAINER" python3 -c "$code" >/dev/null 2>&1 && { ok "Pinry is up"; return 0; }; sleep 3; done
  err "Pinry did not come back — check: docker logs $CONTAINER"; return 1
}

# ------------------------------------------------------------------ main
find_container
if [[ -n $RESTORE ]]; then restore "$RESTORE"; exit; fi
while :; do
  backup_once
  ((INTERVAL > 0)) || break
  sleep "$INTERVAL"
done
