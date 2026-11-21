#!/usr/bin/env bash
# pinry_media_watch.sh — hunt for webshells / non-images in Pinry's upload (media) dir
# Target: Lubuntu/Ubuntu 22.04. Deps: bash, coreutils, findutils, grep (file/docker optional).
# Run as root. Report-only by default; -q moves ALERT files to quarantine (never deletes).
#
#   sudo ./pinry_media_watch.sh                 # auto-detect media dir(s), scan once, check nginx
#   sudo ./pinry_media_watch.sh -i 30           # rescan every 30s (only new/changed files after 1st pass)
#   sudo ./pinry_media_watch.sh -d /data/static/media -i 30 -q
set -uo pipefail

INTERVAL=0; QUARANTINE=0; DIRS=()
LOG=/var/log/pinry_media_watch.log
QDIR=/root/pinry_quarantine

usage(){ sed -n '2,10p' "$0"; echo "Options: -d DIR (repeatable)  -i SECS  -q (quarantine)  -l LOGFILE"; exit 0; }
while getopts "d:i:ql:h" o; do
  case $o in d) DIRS+=("${OPTARG%/}");; i) INTERVAL=$OPTARG;; q) QUARANTINE=1;; l) LOG=$OPTARG;; *) usage;; esac
done
[[ $EUID -eq 0 ]] || echo "[!] not root — some files/containers may be unreadable" >&2

if [[ -t 1 ]]; then R=$'\e[1;31m' Y=$'\e[1;33m' G=$'\e[32m' C=$'\e[36m' N=$'\e[0m'; else R= Y= G= C= N=; fi
log(){ # lvl msg
  local lvl=$1; shift; local ts; printf -v ts '%(%F %T)T' -1
  echo "$ts [$lvl] $*" >>"$LOG" 2>/dev/null
  case $lvl in ALERT) c=$R;; WARN) c=$Y;; OK) c=$G;; *) c=$C;; esac
  echo "${c}$ts [$lvl]${N} $*"
}

# Pinry never needs these; ".php.jpg" style double extensions are caught too
BAD_EXT='\.(php[0-9]?|phtml|pht|phar|inc|py|pyc|pl|cgi|rb|sh|bash|jsp|jspx|asp|aspx|ashx|war|exe|dll|elf|so|js|mjs|html?|xhtml|shtml|htaccess|htpasswd|conf|svgz?)(\.|$)'
CODE_RE='<\?php|<\?=|<script|eval\(|base64_decode|gzinflate|str_rot13|assert\(|shell_exec|passthru|proc_open|popen\(|__import__|subprocess|os\.system|/bin/(ba)?sh|bash -i|nc -e|/dev/tcp/'

magic_ok(){ # 0 if file starts with real image magic bytes (jpg/png/gif/webp/bmp)
  local h; h=$(od -An -tx1 -N12 -- "$1" 2>/dev/null | tr -d ' \n')
  case $h in
    ffd8ff*|89504e470d0a1a0a*|474946383?61*|424d*|52494646????????57454250*) return 0;;
  esac
  return 1
}

detect_dirs(){
  local roots=() c src dst
  if command -v docker >/dev/null 2>&1; then
    for c in $(docker ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null | grep -i pinry | cut -d' ' -f1); do
      while read -r src dst; do [[ -n ${src:-} ]] && roots+=("$src"); done \
        < <(docker inspect -f '{{range .Mounts}}{{.Source}} {{.Destination}}{{"\n"}}{{end}}' "$c" 2>/dev/null)
      src=$(docker inspect -f '{{.GraphDriver.Data.MergedDir}}' "$c" 2>/dev/null)
      [[ -d $src ]] && roots+=("$src/data" "$src/pinry" "$src/srv" "$src/app")
    done
  fi
  for c in /data /srv/pinry /opt/pinry /var/www/pinry /home/*/pinry /root/pinry; do [[ -d $c ]] && roots+=("$c"); done
  while read -r c; do roots+=("$(dirname "$c")"); done < <(
    find / -xdev \( -path /proc -o -path /sys -o -path /snap \) -prune -o \
      -type f -name 'local_settings.py' -path '*pinry*' -printf '%h\n' 2>/dev/null | head -20)
  for c in "${roots[@]}"; do
    [[ -d $c ]] && find "$c" -maxdepth 5 -type d -name media \
      -not -path '*/site-packages/*' -not -path '*/node_modules/*' -not -path '*/dist-packages/*' 2>/dev/null
  done | sort -u
}

quarantine(){ # file mediadir
  local dest="$QDIR/$RUN_ID/${1#$2/}"
  mkdir -p "$(dirname "$dest")" && mv -- "$1" "$dest" && chmod 000 "$dest" \
    && { log ALERT "  -> quarantined to $dest"; unset 'CUR[$1]'; } || log WARN "  -> quarantine FAILED for $1"
}

check_file(){ # file mediadir
  local f=$1 d=$2 name lname tgt sev=WARN reasons=()
  if [[ -L $f ]]; then
    tgt=$(readlink -f -- "$f")
    [[ $tgt == "$d"/* ]] || { log ALERT "symlink escapes media dir: $f -> $tgt"; ((ALERTS++)); ((QUARANTINE)) && quarantine "$f" "$d"; }
    return
  fi
  [[ -f $f ]] || { log WARN "non-regular file (fifo/socket/device): $f"; return; }
  name=${f##*/}; lname=${name,,}
  [[ $lname =~ $BAD_EXT ]] && { reasons+=("bad extension .${BASH_REMATCH[1]}"); sev=ALERT; }
  [[ $lname == .* ]] && reasons+=("hidden file")
  if ! magic_ok "$f"; then
    if grep -a -q -i -m1 '<svg' -- "$f" 2>/dev/null; then reasons+=("SVG (can carry JS)"); sev=ALERT
    else reasons+=("NOT an image by magic bytes: $(file -b -- "$f" 2>/dev/null | cut -c1-50)"); sev=ALERT; fi
  fi
  grep -a -q -E -i -m1 "$CODE_RE" -- "$f" 2>/dev/null && { reasons+=("contains code strings (polyglot?)"); sev=ALERT; }
  [[ -u $f || -g $f ]] && { reasons+=("setuid/setgid bit"); sev=ALERT; }
  [[ -x $f ]] && reasons+=("executable bit")
  ((${#reasons[@]})) || return
  local IFS=';'; log "$sev" "$f :: ${reasons[*]} :: $(stat -c '%U:%G %a %s bytes, mtime %y' -- "$f" | cut -d. -f1)"
  if [[ $sev == ALERT ]]; then ((ALERTS++)); ((QUARANTINE)) && quarantine "$f" "$d"; fi
}

check_nginx(){
  local conf="" c
  if command -v nginx >/dev/null 2>&1; then conf+=$(nginx -T 2>/dev/null); fi
  [[ -z $conf && -d /etc/nginx ]] && conf+=$(cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null)
  if command -v docker >/dev/null 2>&1; then
    for c in $(docker ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null | grep -i pinry | cut -d' ' -f1); do
      conf+=$'\n'$(docker exec "$c" sh -c 'nginx -T 2>/dev/null || cat /etc/nginx/nginx.conf /etc/nginx/conf.d/* /etc/nginx/sites-enabled/* 2>/dev/null' 2>/dev/null)
    done
  fi
  [[ -z ${conf//[[:space:]]/} ]] && { log INFO "nginx: no config found (not nginx-fronted?) — skip"; return; }
  log INFO "---- nginx config review ----"
  grep -n -E '^\s*autoindex\s+on' <<<"$conf" | while read -r l; do log WARN "nginx: directory listing enabled: $l"; done
  grep -n -E 'fastcgi_pass|\.php|php-fpm|cgi-bin' <<<"$conf" | while read -r l; do log ALERT "nginx: PHP/CGI handler (Pinry never needs this): $l"; done
  grep -q -E 'X-Content-Type-Options' <<<"$conf" || log WARN "nginx: no 'X-Content-Type-Options nosniff' header"
  # print every location block that serves media/static for eyeball review
  awk '/location[^{]*(media|static)/{p=1;depth=0} p{print "    " $0; n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth+=n-m; if(depth<=0 && n+m>0){p=0; print ""}}' <<<"$conf" \
    | while IFS= read -r l; do echo "${C}${l}${N}"; done
  grep -q -E 'location[^{]*media' <<<"$conf" || log INFO "nginx: no explicit /media location found"
}

# ---------------- main ----------------
printf -v RUN_ID '%(%Y%m%d_%H%M%S)T' -1
if ((${#DIRS[@]} == 0)); then
  mapfile -t DIRS < <(detect_dirs)
  ((${#DIRS[@]})) || { log ALERT "could not find a Pinry media dir — rerun with -d /path/to/media"; exit 1; }
fi
for i in "${!DIRS[@]}"; do DIRS[i]=$(readlink -f -- "${DIRS[i]}"); done
for d in "${DIRS[@]}"; do log INFO "watching: $d ($(find "$d" -xdev ! -type d 2>/dev/null | wc -l) files)"; done
check_nginx

declare -A PREV=()
PASS=0
while :; do
  ALERTS=0; NEW=0; CHG=0; DEL=0
  declare -A CUR=()
  for d in "${DIRS[@]}"; do
    [[ -d $d ]] || { log ALERT "media dir GONE: $d"; continue; }
    while IFS= read -r -d '' rec; do
      meta=${rec%% *}; rest=${rec#* }; meta+=" ${rest%% *}"; f=${rest#* }   # "size mtime path"
      CUR["$f"]=$meta
      if ((PASS == 0)); then check_file "$f" "$d"
      elif [[ -z ${PREV["$f"]+x} ]]; then ((NEW++)); log INFO "new file: $f"; check_file "$f" "$d"
      elif [[ ${PREV["$f"]} != "$meta" ]]; then ((CHG++)); log WARN "existing file MODIFIED (Pinry never edits uploads): $f"; check_file "$f" "$d"
      fi
    done < <(find "$d" -xdev ! -type d -printf '%s %T@ %p\0' 2>/dev/null)
  done
  if ((PASS > 0)); then
    for f in "${!PREV[@]}"; do [[ -z ${CUR["$f"]+x} ]] && { ((DEL++)); log WARN "file DELETED: $f"; }; done
    ((DEL >= 10)) && log ALERT "$DEL files deleted in one interval — possible wipe; check backups"
  fi
  if ((PASS == 0)); then
    ((ALERTS)) && log ALERT "initial scan: $ALERTS suspicious file(s) — log: $LOG" || log OK "initial scan clean (${#CUR[@]} files)"
  elif ((NEW + CHG + DEL + ALERTS)); then
    log INFO "pass $PASS: new=$NEW changed=$CHG deleted=$DEL alerts=$ALERTS"
  fi
  PREV=(); for f in "${!CUR[@]}"; do PREV["$f"]=${CUR["$f"]}; done
  unset CUR
  ((INTERVAL > 0)) || break
  ((PASS++)); sleep "$INTERVAL"
done
