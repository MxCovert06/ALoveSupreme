# Pinry — CCDC defense toolkit

Scripts for defending a [Pinry](https://github.com/pinry/pinry) (Django image pinboard) box during CCDC.
Target box: Ubuntu/Lubuntu 22.04, Pinry in Docker (`getpinry/pinry`) or bare metal. Everything uses only what ships with the OS (bash, coreutils, python3 stdlib). Run as root.

| File | What it does |
|---|---|
| `pinry_backup_bm.sh` | Backup/restore for a **bare-metal** install (`/pinry` + `/data`): consistent SQLite copy, app/data/nginx/startup-unit tarballs, checksums, restore with evidence kept |
| `pinry_backup.sh` | Backup/restore of a **Docker** container: consistent SQLite copy, `/data`, app code, `/etc/nginx`, `docker commit` snapshot, and a generated `recreate.sh` |
| `pinry_fix.py` | Patches the code vulns in `core/models.py`, `core/serializers.py`, `users/views.py` (no settings/key changes) |
| `pinry_apply_patches.sh` | Full patch set (code + settings + nginx) with checks, health test, auto-rollback |
| `pinry_ccdc.patch` | The same fixes as a unified diff (`patch -p1 < pinry_ccdc.patch` from the Pinry base folder) |
| `pinry_integrity.py` | Baseline + enforce file integrity of code, settings, nginx, Django/DRF (quarantine new, restore modified/deleted) |
| `pinry_log_watch.sh` | Live alerting on nginx logs (admin hits, brute force, scanners, attack strings, webshell requests, mass deletes) + outbound-connection watch |
| `pinry_media_watch.sh` | Hunts webshells / non-images / polyglots in the upload dir, reviews nginx config |

## Order of operations

```bash
sudo ./pinry_backup.sh                                   # 1. snapshot before touching anything
sudo ./pinry_log_watch.sh -v                             # 2. watch a few scoring rounds: learn scorer IP + requests
docker cp pinry_fix.py <c>:/tmp/ && \
  docker exec <c> python3 /tmp/pinry_fix.py /pinry       # 3. patch code
docker exec <c> sh -c 'cd /pinry && python manage.py check' && docker restart <c>
sudo python3 pinry_integrity.py init --docker <c>        # 4. baseline the patched state
sudo systemd-run --unit=pinry-integrity -p Restart=always \
  python3 /root/pinry_integrity.py watch --interval 10 --report-only
sudo systemd-run --unit=pinry-logwatch -p Restart=always /root/pinry_log_watch.sh -w <scorer-ip>
sudo systemd-run --unit=pinry-mediawatch -p Restart=always /root/pinry_media_watch.sh -i 30
sudo journalctl -f -u pinry-integrity -u pinry-logwatch -u pinry-mediawatch | grep -E --color 'ALERT|WARN'
```

## Vulnerabilities fixed

| # | Where | Issue | Fix |
|---|---|---|---|
| 1 | `core/models.py` `delete_pin_images` + `core/serializers.py` | Pin someone else's image via `image_by_id`, delete your pin → their image and every pin using it is cascade-deleted (sequential IDs = wipe the site) | Reject foreign `image_by_id`; only delete an image when no other pin uses it |
| 2 | `core/models.py` `create_for_url` | SSRF: fetches any URL, follows redirects, no timeout/size cap | http(s) only, internal IPs blocked, each redirect re-checked, 10s timeout, 10 MB cap, `PIN_FETCH_ALLOW_HOSTS` escape hatch |
| 3 | SPA `:href="referer"` | Stored XSS via `javascript:` pin source | Server-side http(s)-only validation of `url`/`referer` |
| 4 | SPA `niceLinks()` | Quotes not escaped → attribute-injection XSS in descriptions | Strip `"` and `` ` `` from descriptions |
| 5 | `create_for_url` filename | Remote filename kept (`x.html` polyglot served from `/media`) | Extension derived from real image format |
| 6 | `users/views.py` `login_user` | No brute-force protection | 10 failures / IP / 5 min lockout (per-IP so the scoring account can't be locked out) |
| 7 | `settings/base.py` | BasicAuth on the API (CSRF-free password spraying), no throttling | BasicAuth removed, DRF throttles |
| 8 | `users/serializers.py` | Every user's email exposed on every pin | Email only returned to its owner |
| 9 | nginx `/media` | Logging off, uploads served by extension | Logged, image types only, `nosniff` + sandbox CSP, script extensions 403 |
| 10 | settings | Default `SECRET_KEY`, open registration, public API docs | Rotate key, registration off, docs removed |

**Scoring caveats:** registration off breaks a scorer that signs up (`-R`); the SSRF block breaks pin-from-URL against an internal host (`PIN_FETCH_ALLOW_HOSTS` / `-a`); removing BasicAuth breaks a scorer using `curl -u`; `-t` (token wipe) breaks a token-based scorer.

## pinry_fix.py

```bash
python3 pinry_fix.py /pinry --dry-run
python3 pinry_fix.py /pinry
```
Errors out if the base folder is missing or isn't Pinry. All-or-nothing: every edit is verified and the result compiled before anything is written; if expected code isn't found exactly once (different version or **tampered**), nothing changes. Backups: `<file>.bak-<timestamp>`. Re-runs skip patched files.

## pinry_integrity.py

Watches: whole app dir, `local_settings.py`, `/etc/nginx`, Django + DRF packages, site-packages auto-run hooks (`*.pth`, `sitecustomize.py`, `usercustomize.py`). Not uploads or the DB.

In `watch` mode: **new** file → quarantined; **modified** → tampered copy quarantined, clean copy restored; **deleted** → restored; **mode/owner change** → reset. New files are also grepped for in the access log to show who requested them. `.pyc` files are accepted only if their header matches the current `.py` source.

```bash
sudo python3 pinry_integrity.py init --docker <c>          # or: init --app /path --python /venv/bin/python
sudo python3 pinry_integrity.py check                      # one pass, report only
sudo python3 pinry_integrity.py watch --interval 10        # enforce (add --report-only for alerts only)
sudo python3 pinry_integrity.py update --path /pinry/core/views.py   # accept YOUR change
sudo python3 pinry_integrity.py update                     # full re-baseline
sudo python3 pinry_integrity.py status                     # baseline + last quarantined items
```

- Run it on the **host** — in Docker mode it reads the container filesystem from outside, so it can't be seen or killed from inside the container.
- Baseline **after** patching and one container restart (startup `chown`s `/data`).
- Enforce mode reverts **your** edits too: stop the unit → change → `update --path` → start.
- State: `/root/pinry_integrity/` (`baseline.json`, `store/` clean copies, `quarantine/INDEX.log`). Keep an off-box copy.
- Limits: 10s polling window; protects files, not running processes (restart the container after a MODIFIED alert); host root can disable it.

## pinry_backup.sh

```bash
sudo ./pinry_backup.sh                      # backup now
sudo ./pinry_backup.sh -i 900 -k 8 -o /mnt/elsewhere   # every 15 min, keep 8, second copy
sudo ./pinry_backup.sh -l                   # list
sudo ./pinry_backup.sh -r <dir>             # restore data + code + nginx (safety backup taken first)
sudo ./pinry_backup.sh -r <dir> -d          # data only
```
Restore moves the current DB/media/settings/logs to `/data/.pre_restore_<ts>` (evidence) and verifies checksums. If the container is gone: run `<dir>/recreate.sh`, then restore with `-d`.

## pinry_backup_bm.sh (bare metal)

```bash
sudo ./pinry_backup_bm.sh                       # backup now (defaults: -a /pinry -d /data)
sudo ./pinry_backup_bm.sh -i 900 -k 8 -o /mnt/elsewhere
sudo ./pinry_backup_bm.sh -l
sudo ./pinry_backup_bm.sh -r <dir>              # restore app + data + nginx
sudo ./pinry_backup_bm.sh -r <dir> -D           # data only
```
Errors out if the app folder is missing or has no `manage.py`. Finds the DB from the settings files without running Pinry code. Restore takes a safety backup first, verifies checksums, moves current DB/media/settings/logs to `/data/.pre_restore_<ts>` and old code to `/pinry.pre_restore_<ts>`, then reloads gunicorn and checks that the site responds.

## pinry_apply_patches.sh

```bash
sudo ./pinry_apply_patches.sh -n            # dry run
sudo ./pinry_apply_patches.sh [-a scorer-host] [-R] [-t]
sudo ./pinry_apply_patches.sh -u /root/pinry_patch_backup/<ts>   # rollback
```
Patches embedded. Per file: exact upstream → replaced; drifted → fuzzy patch + warning; already patched → skipped; too different → refused. Adds a hardening block to `local_settings.py` (new `SECRET_KEY`, `DEBUG=False`, registration off unless `-R`). Runs `manage.py check` + `nginx -t`, restarts, health-checks, auto-rolls back on failure.

## Log + media watchers

```bash
sudo ./pinry_log_watch.sh -o               # one-shot triage of existing logs
sudo ./pinry_log_watch.sh -r -w <scorer>   # replay then follow
sudo ./pinry_media_watch.sh -i 30 [-q]     # -q quarantines instead of reporting
```
Docker Pinry logs to `/data/nginx-access.log`; `/media` requests are only logged after the nginx fix.

## Testing status

Tested against fake installs and a Docker stand-in, not a live `getpinry/pinry` container. Run `--dry-run` / `check` modes on the real box first.
