#!/usr/bin/env bash
# pinry_log_watch.sh — live alerting on Pinry web logs + outbound connections from the app
# Target: Lubuntu/Ubuntu 22.04. Deps: bash, coreutils, iproute2 (ss), util-linux (nsenter); docker optional.
# Reads nginx "combined" format; unparsable lines still get raw attack-string checks.
#
#   sudo ./pinry_log_watch.sh                      # auto: /var/log/nginx/access.log and/or pinry container logs
#   sudo ./pinry_log_watch.sh -r                   # replay existing log first (triage), then follow
#   sudo ./pinry_log_watch.sh -o -f access.log     # one-shot triage of a log, print summary, exit
#   sudo ./pinry_log_watch.sh -w 10.0.0.5,10.0.0.6 # mute scoring engine / your own IPs
set -uo pipefail

FILES=(); CONTAINERS=(); REPLAY=0; ONCE=0; VERBOSE=0; EGRESS=1; EGRESS_INT=5
WHITELIST=","; LOG=/var/log/pinry_log_watch.log
BRUTE=10      # login POSTs per IP per minute
NOTFOUND=30   # 404s per IP per minute (dir busting)
DELBURST=10   # DELETEs per IP per minute (wipe/deface)
FLOOD=300     # requests per IP per minute

usage(){ sed -n '2,11p' "$0"; cat <<'E'
Options: -f FILE (repeatable)  -c CONTAINER (repeatable)  -r replay+follow  -o replay only, then exit
         -w ip,ip whitelist    -v show INFO events        -n no egress watch  -e SECS egress poll  -l LOGFILE
E
exit 0; }
while getopts "f:c:row:vne:l:h" o; do
  case $o in f) FILES+=("$OPTARG");; c) CONTAINERS+=("$OPTARG");; r) REPLAY=1;; o) ONCE=1; REPLAY=1; EGRESS=0;;
    w) WHITELIST=",$OPTARG,";; v) VERBOSE=1;; n) EGRESS=0;; e) EGRESS_INT=$OPTARG;; l) LOG=$OPTARG;; *) usage;; esac
done
[[ $EUID -eq 0 ]] || echo "[!] not root — logs/egress watch may fail" >&2

if [[ -t 1 ]]; then R=$'\e[1;31m' Y=$'\e[1;33m' C=$'\e[36m' D=$'\e[2m' N=$'\e[0m'; else R= Y= C= D= N=; fi
declare -A LAST_ALERT=() WSTART=() WCOUNT=() SEEN=() TOTAL=() NALERT=()
NOW=0

log(){ # lvl dedupe-key msg   (same key suppressed for 60s)
  local lvl=$1 key=$2; shift 2
  if [[ -n $key ]]; then
    (( NOW - ${LAST_ALERT[$key]:-0} < 60 )) && return
    LAST_ALERT[$key]=$NOW
  fi
  local ts; printf -v ts '%(%F %T)T' -1
  echo "$ts [$lvl] $*" >>"$LOG" 2>/dev/null
  NALERT[$lvl]=$(( ${NALERT[$lvl]:-0} + 1 ))
  case $lvl in ALERT) echo "${R}$ts [ALERT]${N} $*";; WARN) echo "${Y}$ts [WARN]${N}  $*";;
    *) ((VERBOSE)) && echo "${D}$ts [INFO]  $*${N}";; esac
  return 0
}
bump(){ # key window -> sets CNT
  local k=$1 w=$2
  if (( NOW - ${WSTART[$k]:-0} > w )); then WSTART[$k]=$NOW; WCOUNT[$k]=0; fi
  WCOUNT[$k]=$(( ${WCOUNT[$k]} + 1 )); CNT=${WCOUNT[$k]}
}
urldecode(){ local s=${1//+/ }; printf -v DEC '%b' "${s//%/\\x}"; }

ATTACK_RE='\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|/proc/self|<script|javascript:|onerror=|union.+select|select.+from|sleep\(|benchmark\(|\$\{jndi|\{\{.*\}\}|;[[:space:]]*(wget|curl|nc|bash|sh|python)|\|[[:space:]]*(sh|bash)|`|\$\(|/\.git|/\.env|/\.ssh|wp-(admin|login)|\.php|cmd=|exec=|/bin/(ba)?sh|base64'
SCANNER_RE='sqlmap|nikto|nmap|masscan|gobuster|dirbuster|feroxbuster|ffuf|wfuzz|nuclei|zgrab|hydra|burp|whatweb|metasploit|wpscan|acunetix|openvas'
SCRIPT_UA_RE='curl|wget|python-requests|python-urllib|aiohttp|go-http-client|libwww|powershell|httpie|java/'
IMG_EXT_RE='\.(jpe?g|png|gif|webp|bmp)$'
LINE_RE='([0-9a-fA-F:.]+) - ([^ ]+) \[([^]]+)\] "([A-Z]+) ([^ "]*)[^"]*" ([0-9]{3}) ([0-9-]+) "([^"]*)" "([^"]*)"'
LAST_TS=""

set_now_from(){ # nginx time "21/Nov/2026:10:03:01 -0500" -> epoch (cached per second)
  if ((REPLAY)) && [[ $1 != "$LAST_TS" ]]; then
    local t=${1/:/ }; t=${t//\// }
    NOW=$(date -d "$t" +%s 2>/dev/null || printf '%(%s)T' -1); LAST_TS=$1
  elif ((! REPLAY)); then printf -v NOW '%(%s)T' -1; fi
}

process(){
  local line=$1 ip user ts m path st ua p lp
  if [[ ! $line =~ $LINE_RE ]]; then
    ((REPLAY)) || printf -v NOW '%(%s)T' -1
    urldecode "$line"
    [[ ${DEC,,} =~ $ATTACK_RE ]] && log WARN "raw:${BASH_REMATCH[0]}" "attack string in unparsed line: ${line:0:200}"
    return
  fi
  ip=${BASH_REMATCH[1]} ts=${BASH_REMATCH[3]} m=${BASH_REMATCH[4]} path=${BASH_REMATCH[5]} st=${BASH_REMATCH[6]} ua=${BASH_REMATCH[9]}
  set_now_from "$ts"
  [[ $WHITELIST == *",$ip,"* ]] && return
  TOTAL[$ip]=$(( ${TOTAL[$ip]:-0} + 1 ))
  urldecode "$path"; p=${DEC,,}; lp=${p%%\?*}
  local who="$ip $m $path -> $st"

  [[ -z ${SEEN[$ip]+x} ]] && { SEEN[$ip]=1; log INFO "" "new client IP $ip (UA: ${ua:0:80})"; }

  # recon / tooling
  [[ ${ua,,} =~ $SCANNER_RE ]] && log ALERT "scan:$ip" "SCANNER UA '${BASH_REMATCH[0]}' from $ip"
  [[ ${ua,,} =~ $SCRIPT_UA_RE ]] && log WARN "ua:$ip" "scripted client '${BASH_REMATCH[0]}' from $ip (whitelist with -w if scorer)"
  [[ $p =~ $ATTACK_RE ]] && log ALERT "atk:$ip:$lp" "ATTACK PATTERN '${BASH_REMATCH[0]}': $who"

  # admin panel
  if [[ $lp == /admin* ]]; then
    if [[ $m == POST && $lp == */login* && $st == 302 ]]; then log ALERT "" "DJANGO ADMIN LOGIN SUCCESS from $ip — verify it's you!"
    else log ALERT "adm:$ip" "admin panel access: $who"; fi
  fi

  # logins / brute force
  if [[ $m == POST && $lp =~ login|token|auth|session ]]; then
    bump "login:$ip" 60
    ((CNT >= BRUTE)) && log ALERT "bf:$ip" "BRUTE FORCE: $CNT login POSTs/min from $ip ($lp)"
    if [[ $st == 2* || $st == 3* ]] && (( ${WCOUNT["login:$ip"]} >= 5 )); then
      log ALERT "" "login SUCCESS after $CNT attempts from $ip — likely cracked account"
    elif [[ $st == 2* || $st == 3* ]]; then log INFO "" "login ok: $who"; fi
  fi

  # account creation
  if [[ $lp =~ regist|signup|sign-up ]] || [[ $m == POST && $lp =~ /users/?$ ]]; then
    [[ $st == 2* || $st == 3* ]] && [[ $m == POST ]] && log ALERT "" "ACCOUNT CREATED/REGISTERED: $who" \
      || log WARN "reg:$ip" "registration attempt: $who"
  fi

  # writes / wipes
  if [[ $m =~ ^(PUT|PATCH|DELETE)$ ]]; then
    log INFO "" "write: $who"
    if [[ $m == DELETE ]]; then bump "del:$ip" 60
      ((CNT >= DELBURST)) && log ALERT "del:$ip" "MASS DELETE: $CNT DELETEs/min from $ip — wipe/deface? check backups"; fi
  fi

  # webshell access in upload/static dirs
  if [[ $lp == /media/* || $lp == /static/* ]]; then
    if [[ $lp == /media/* && ! $lp =~ $IMG_EXT_RE ]]; then log ALERT "ws:$lp" "NON-IMAGE in /media requested (webshell?): $who"
    elif [[ $p == *\?* && $lp == /media/* ]]; then log ALERT "wsq:$ip" "query string on media file (webshell params?): $who"; fi
  fi

  # bursts
  [[ $st == 404 ]] && { bump "404:$ip" 60; ((CNT >= NOTFOUND)) && log ALERT "404:$ip" "DIR BUSTING: $CNT 404s/min from $ip"; }
  if [[ $st == 5* ]]; then
    log WARN "500:$lp" "server error: $who"
    bump "5xx" 60; ((CNT >= 5)) && log ALERT "5xx" "$CNT server errors/min — app breaking or being exploited (check service!)"
  fi
  bump "rate:$ip" 60; ((CNT >= FLOOD)) && log WARN "flood:$ip" "high rate: $CNT req/min from $ip"
}

# ---------- outbound connection watch (SSRF / reverse shells / C2) ----------
app_pids(){
  local c
  if command -v docker >/dev/null 2>&1; then
    for c in $(docker ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null | grep -i pinry | cut -d' ' -f1); do
      docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null
    done
  fi
  pgrep -f 'gunicorn|uwsgi|manage\.py|pinry' 2>/dev/null | head -1
}
is_internal(){ [[ $1 =~ ^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|\[::1\]|fe80|fc|fd) ]]; }
egress_loop(){
  declare -A seen=()
  while :; do
    printf -v NOW '%(%s)T' -1
    for pid in $(app_pids | sort -u); do
      [[ -d /proc/$pid ]] || continue
      local listen; listen=" $(nsenter -t "$pid" -n ss -Htln 2>/dev/null | awk '{n=split($4,a,":"); printf "%s ", a[n]}') "
      while read -r _ _ _ laddr raddr procinfo; do
        local lport=${laddr##*:} rport=${raddr##*:} rip=${raddr%:*}
        [[ $listen == *" $lport "* ]] && continue                       # inbound client conn
        if [[ $rip =~ ^(127\.|\[::1\]|::1) ]] && [[ $listen == *" $rport "* ]]; then continue; fi  # nginx->gunicorn
        local key="$pid|$raddr"; [[ -n ${seen[$key]+x} ]] && continue; seen[$key]=1
        if is_internal "$rip"; then log ALERT "" "OUTBOUND to INTERNAL $raddr from app ns (pid $pid) — SSRF or lateral movement? $procinfo"
        else log WARN "" "outbound to $raddr from app ns (pid $pid) — image fetch or C2/reverse shell? $procinfo"; fi
      done < <(nsenter -t "$pid" -n ss -Htnp state established 2>/dev/null | awk '{print "x","x","x",$3,$4,$5}')
    done
    sleep "$EGRESS_INT"
  done
}

summary(){
  echo; echo "${C}==== summary ====${N}  ALERT=${NALERT[ALERT]:-0} WARN=${NALERT[WARN]:-0}  (full log: $LOG)"
  echo "top talkers:"; for ip in "${!TOTAL[@]}"; do echo "${TOTAL[$ip]} $ip"; done | sort -rn | head -10 | sed 's/^/  /'
}

# ---------- sources ----------
if ((${#FILES[@]} + ${#CONTAINERS[@]} == 0)); then
  for f in /var/log/nginx/access.log /var/log/nginx/pinry*.log; do [[ -f $f ]] && FILES+=("$f"); done
  if command -v docker >/dev/null 2>&1; then
    mapfile -t CONTAINERS < <(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -i pinry | cut -d' ' -f1)
    for c in "${CONTAINERS[@]}"; do   # also grab log files inside the container's data mount, if any
      while read -r src; do for f in "$src"/logs/*access*.log "$src"/*access*.log; do [[ -f $f ]] && FILES+=("$f"); done; done \
        < <(docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$c" 2>/dev/null)
    done
  fi
fi
((${#FILES[@]} + ${#CONTAINERS[@]})) || { echo "no logs found — pass -f /path/access.log or -c container"; exit 1; }
echo "${C}[*] sources:${N} ${FILES[*]:-} ${CONTAINERS[*]:+containers: ${CONTAINERS[*]}}"
echo "${C}[*] whitelist:${N} ${WHITELIST//,/ }  ${C}log:${N} $LOG  ${C}egress watch:${N} $( ((EGRESS)) && echo on || echo off)"

stream(){
  local c
  if ((ONCE)); then
    ((${#FILES[@]})) && cat -- "${FILES[@]}" 2>/dev/null
    for c in "${CONTAINERS[@]}"; do docker logs "$c" 2>&1; done
    return
  fi
  local n=0; ((REPLAY)) && n=+1
  ((${#FILES[@]})) && tail -q -n "$n" -F -- "${FILES[@]}" 2>/dev/null &
  for c in "${CONTAINERS[@]}"; do
    if ((REPLAY)); then docker logs -f "$c" 2>&1 & else docker logs -f --tail 0 "$c" 2>&1 & fi
  done
  wait
}

if ((EGRESS)); then egress_loop & EG_PID=$!; fi
trap 'summary; [[ -n ${EG_PID:-} ]] && kill "$EG_PID" 2>/dev/null; pkill -P $$ 2>/dev/null; exit 0' INT TERM
while IFS= read -r line; do
  process "$line"
done < <(stream)
summary
