#!/usr/bin/env python3
"""pinry_integrity.py - file-integrity enforcement for Pinry (CCDC)

Takes a SHA-256 baseline of everything that should never change at runtime, then watches it:
  NEW file       -> moved to quarantine (evidence kept)
  MODIFIED file  -> modified copy quarantined, known-good copy restored
  DELETED file   -> known-good copy restored
  PERMS changed  -> mode/owner restored (catches setuid, chmod 777, ...)

Watched: the whole Pinry app dir (code, templates, built JS), local_settings.py, /etc/nginx,
Django + DRF packages, and site-packages auto-run hooks (*.pth, sitecustomize/usercustomize).

  sudo python3 pinry_integrity.py init  --docker pinry       # Docker: run on the HOST
  sudo python3 pinry_integrity.py init  --app /srv/pinry     # bare metal
  sudo python3 pinry_integrity.py check                      # one pass, report only
  sudo python3 pinry_integrity.py watch --interval 10        # enforce continuously
  sudo python3 pinry_integrity.py update                     # re-baseline after YOUR changes
  sudo python3 pinry_integrity.py update --path /pinry/core/views.py   # accept one file
  sudo python3 pinry_integrity.py status

Stdlib only. State lives in /root/pinry_integrity (baseline, clean copies, quarantine, log).
"""
import argparse
import fnmatch
import glob
import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import time

STATE = os.environ.get("PINRY_INTEGRITY_DIR", "/root/pinry_integrity")
BASELINE = os.path.join(STATE, "baseline.json")
STORE = os.path.join(STATE, "store")          # clean copies, content-addressed by sha256
QUAR = os.path.join(STATE, "quarantine")
LOG = os.environ.get("PINRY_INTEGRITY_LOG", "/var/log/pinry_integrity.log")
HOOK_NAMES = ("sitecustomize.py", "usercustomize.py")

TTY = sys.stdout.isatty()
COL = {"ALERT": "\033[1;31m", "WARN": "\033[1;33m", "OK": "\033[1;32m", "INFO": "\033[36m"}


def log(level, msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = "%s [%s] %s" % (ts, level, msg)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass
    if TTY:
        print("%s%s [%s]\033[0m %s" % (COL.get(level, ""), ts, level, msg), flush=True)
    else:
        print(line, flush=True)


def die(msg):
    log("ALERT", msg)
    sys.exit(1)


# ------------------------------------------------------------------ target resolution
def docker_json(container):
    try:
        out = subprocess.run(["docker", "inspect", container], capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        die("docker not found on this host")
    if out.returncode != 0:
        return None
    return json.loads(out.stdout)[0]


def resolve_roots(target):
    """Return list of (label, host_path, mode). mode: 'tree' (recursive), 'top' (top-level of dir,
    only hook files), 'file' (single file). Labels are stable across container restarts."""
    roots = []
    if target["kind"] == "docker":
        info = docker_json(target["container"])
        if info is None:
            raise RuntimeError("container '%s' not found (deleted/renamed?)" % target["container"])
        merged = info.get("GraphDriver", {}).get("Data", {}).get("MergedDir")
        if not merged or not os.path.isdir(merged):
            raise RuntimeError("container filesystem not visible (is it running? storage driver overlay2?)")
        app = target["app_in_container"]
        roots.append(("app", merged + app, "tree"))
        roots.append(("nginx", merged + "/etc/nginx", "tree"))
        data_src = next((m["Source"] for m in info.get("Mounts", []) if m.get("Destination") == "/data"), None)
        ls = os.path.join(data_src, "local_settings.py") if data_src else merged + "/data/local_settings.py"
        roots.append(("local_settings", ls, "file"))
        for sp in sorted(glob.glob(merged + "/usr/local/lib/python3*/site-packages")
                         + glob.glob(merged + "/root/.local/lib/python3*/site-packages")
                         + glob.glob(merged + "/usr/lib/python3*/site-packages")
                         + glob.glob(merged + "/usr/lib/python3/dist-packages")):
            tag = "sp:" + sp[len(merged):]
            roots.append((tag + ":hooks", sp, "top"))
            for pkg in ("django", "rest_framework"):
                if os.path.isdir(os.path.join(sp, pkg)):
                    roots.append((tag + ":" + pkg, os.path.join(sp, pkg), "tree"))
    else:
        app = target["app"]
        roots.append(("app", app, "tree"))
        if os.path.isdir("/etc/nginx"):
            roots.append(("nginx", "/etc/nginx", "tree"))
        for sp in target.get("site_packages", []):
            roots.append(("sp:%s:hooks" % sp, sp, "top"))
            for pkg in ("django", "rest_framework"):
                if os.path.isdir(os.path.join(sp, pkg)):
                    roots.append(("sp:%s:%s" % (sp, pkg), os.path.join(sp, pkg), "tree"))
    return roots


def find_site_packages(python):
    code = ("import site,sys,os;p=set(site.getsitepackages()+[site.getusersitepackages()]);"
            "\ntry:\n import django;p.add(os.path.dirname(os.path.dirname(django.__file__)))\n"
            "except Exception: pass\nprint('\\n'.join(x for x in p if os.path.isdir(x)))")
    try:
        out = subprocess.run([python, "-c", code], capture_output=True, text=True, timeout=20)
        return sorted(set(l for l in out.stdout.split("\n") if l.strip()))
    except Exception:
        return []


# ------------------------------------------------------------------ scanning
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entry(path):
    st = os.lstat(path)
    e = {"mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid}
    if stat.S_ISLNK(st.st_mode):
        e["type"] = "link"
        e["target"] = os.readlink(path)
    elif stat.S_ISREG(st.st_mode):
        e["type"] = "file"
        e["sha256"] = sha256(path)
    else:
        e["type"] = "other"
    return e


def is_hook(name):
    return name.endswith(".pth") or name in HOOK_NAMES


def walk_root(root_path, mode, ignore):
    """yield (relpath, abspath)"""
    if mode == "file":
        if os.path.lexists(root_path):
            yield "", root_path
        return
    if not os.path.isdir(root_path):
        return
    if mode == "top":
        for name in sorted(os.listdir(root_path)):
            p = os.path.join(root_path, name)
            if is_hook(name) and not os.path.isdir(p):
                yield name, p
        return
    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
        dirnames.sort()
        # symlinked dirs show up in dirnames but aren't descended; treat them as entries
        for name in sorted(filenames) + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root_path)
            if any(fnmatch.fnmatch(rel, pat) for pat in ignore):
                continue
            yield rel, p


def scan(roots, ignore):
    """{label: {rel: entry}} plus {label: host_path}"""
    snap, paths = {}, {}
    for label, path, mode in roots:
        paths[label] = path
        files = {}
        for rel, p in walk_root(path, mode, ignore):
            try:
                files[rel] = entry(p)
            except (FileNotFoundError, PermissionError):
                continue
        snap[label] = files
    return snap, paths


# ------------------------------------------------------------------ .pyc handling
def pyc_matches_source(pyc_path):
    """A __pycache__ .pyc is legit if its header records the current mtime+size of its .py source.
    (Python regenerates these on start; we can't recompile them because the container's Python
    version may differ from the host's.)"""
    d, name = os.path.split(pyc_path)
    if os.path.basename(d) != "__pycache__" or not name.endswith(".pyc"):
        return False
    src = os.path.join(os.path.dirname(d), name.split(".")[0] + ".py")
    try:
        with open(pyc_path, "rb") as f:
            head = f.read(16)
        st = os.stat(src)
    except OSError:
        return False                       # orphan .pyc with no source -> suspicious
    if len(head) < 16:
        return False
    flags = struct.unpack("<I", head[4:8])[0]
    if flags != 0:                          # hash-based pyc: just require source to exist
        return True
    mtime, size = struct.unpack("<II", head[8:16])
    return mtime == (int(st.st_mtime) & 0xFFFFFFFF) and size == (st.st_size & 0xFFFFFFFF)


# ------------------------------------------------------------------ state
def load_baseline():
    if not os.path.isfile(BASELINE):
        die("no baseline yet - run: sudo python3 %s init --docker <container> | --app <path>" % sys.argv[0])
    with open(BASELINE) as f:
        return json.load(f)


def save_baseline(b):
    tmp = BASELINE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(b, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, BASELINE)


def store_copy(path, e):
    if e.get("type") != "file":
        return
    dst = os.path.join(STORE, e["sha256"])
    if not os.path.exists(dst):
        shutil.copyfile(path, dst)
        os.chmod(dst, 0o400)


def restore(path, e):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if e["type"] == "link":
        if os.path.lexists(path):
            os.unlink(path)
        os.symlink(e["target"], path)
    elif e["type"] == "file":
        src = os.path.join(STORE, e["sha256"])
        if not os.path.exists(src):
            raise RuntimeError("clean copy missing from store")
        tmp = path + ".integrity-tmp"
        shutil.copyfile(src, tmp)
        os.chmod(tmp, e["mode"])
        try:
            os.chown(tmp, e["uid"], e["gid"])
        except OSError:
            pass
        os.replace(tmp, path)


def quarantine(path, label, rel, why):
    ts = time.strftime("%Y%m%d_%H%M%S")
    dst_dir = os.path.join(QUAR, ts, label.replace("/", "_").replace(":", "_"), os.path.dirname(rel))
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, os.path.basename(path) or "file")
    try:
        digest = sha256(path) if os.path.isfile(path) and not os.path.islink(path) else "-"
    except OSError:
        digest = "-"
    shutil.move(path, dst)
    try:
        if not os.path.islink(dst):
            os.chmod(dst, 0)
    except OSError:
        pass
    with open(os.path.join(QUAR, "INDEX.log"), "a") as f:
        f.write("%s\t%s\t%s\tsha256=%s\t%s\n" % (ts, why, path, digest, dst))
    return dst


def find_access_log(target):
    cands = ["/var/log/nginx/access.log"]
    if target["kind"] == "docker":
        info = docker_json(target["container"]) or {}
        data_src = next((m["Source"] for m in info.get("Mounts", []) if m.get("Destination") == "/data"), None)
        if data_src:
            cands.insert(0, os.path.join(data_src, "nginx-access.log"))
    return [c for c in cands if os.path.isfile(c)]


def who_planted(target, name):
    """grep the web access log for the file name -> hints at the attacker IP"""
    for lf in find_access_log(target):
        try:
            with open(lf, "rb") as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - 5 * 1024 * 1024))
                hits = [l.decode("utf-8", "replace").strip() for l in f if name.encode() in l]
        except OSError:
            continue
        for h in hits[-3:]:
            log("WARN", "    access-log hit (%s): %s" % (os.path.basename(lf), h[:220]))


# ------------------------------------------------------------------ commands
def build_target(args):
    if args.docker:
        info = docker_json(args.docker)
        if info is None:
            die("container '%s' not found (docker ps)" % args.docker)
        merged = info.get("GraphDriver", {}).get("Data", {}).get("MergedDir", "")
        app = args.app_in_container
        if not os.path.isfile(os.path.join(merged + app, "manage.py")):
            die("no manage.py at %s inside container (use --app-in-container)" % app)
        return {"kind": "docker", "container": args.docker, "app_in_container": app}
    if args.app:
        app = os.path.abspath(args.app)
        if not os.path.isfile(os.path.join(app, "manage.py")):
            die("%s is not a Pinry base folder (no manage.py)" % app)
        sps = args.site_packages or find_site_packages(args.python)
        if not sps:
            log("WARN", "no site-packages found (pass --python /path/to/venv/bin/python) - packages not watched")
        return {"kind": "host", "app": app, "site_packages": sps}
    die("give --docker <container> or --app <path>")


def cmd_init(args):
    if os.path.isfile(BASELINE) and not args.force:
        die("baseline exists - use 'update' to re-baseline, or 'init --force' to start over")
    target = build_target(args)
    for d in (STATE, STORE, QUAR):
        os.makedirs(d, exist_ok=True)
    os.chmod(STATE, 0o700)
    roots = resolve_roots(target)
    snap, paths = scan(roots, args.ignore)
    n = 0
    for label, files in snap.items():
        for rel, e in files.items():
            store_copy(os.path.join(paths[label], rel) if rel else paths[label], e)
            n += 1
    save_baseline({"target": target, "ignore": args.ignore, "created": time.time(), "files": snap})
    for label, path, mode in roots:
        log("INFO", "  %-38s %5d files  %s" % (label, len(snap[label]), path))
    log("OK", "baseline created: %d files, clean copies in %s" % (n, STORE))


def one_pass(b, enforce, quiet_ok=False):
    target, ignore = b["target"], b.get("ignore", [])
    try:
        roots = resolve_roots(target)
    except RuntimeError as e:
        log("ALERT", str(e))
        return 1
    snap, paths = scan(roots, ignore)
    problems = 0
    for label, base_files in b["files"].items():
        if label not in paths:
            log("WARN", "watched area '%s' no longer present" % label)
            continue
        cur = snap.get(label, {})
        root = paths[label]
        p_of = lambda rel: os.path.join(root, rel) if rel else root
        # NEW
        for rel in sorted(set(cur) - set(base_files)):
            p = p_of(rel)
            if rel.endswith(".pyc") and pyc_matches_source(p):
                continue                    # regenerated bytecode for an unchanged source
            problems += 1
            if enforce:
                dst = quarantine(p, label, rel, "NEW")
                log("ALERT", "NEW file quarantined: %s -> %s" % (p, dst))
            else:
                log("ALERT", "NEW file: %s" % p)
            who_planted(target, os.path.basename(rel))
        # MODIFIED / PERMS
        for rel in sorted(set(cur) & set(base_files)):
            c, e, p = cur[rel], base_files[rel], p_of(rel)
            content_changed = c["type"] != e["type"] or c.get("sha256") != e.get("sha256") \
                or c.get("target") != e.get("target")
            if content_changed:
                if rel.endswith(".pyc") and pyc_matches_source(p):
                    continue
                problems += 1
                if enforce:
                    dst = quarantine(p, label, rel, "MODIFIED")
                    try:
                        restore(p, e)
                        log("ALERT", "MODIFIED file restored: %s (tampered copy -> %s)" % (p, dst))
                    except Exception as ex:
                        log("ALERT", "MODIFIED file %s - RESTORE FAILED: %s" % (p, ex))
                else:
                    log("ALERT", "MODIFIED file: %s" % p)
            elif (c["mode"], c["uid"], c["gid"]) != (e["mode"], e["uid"], e["gid"]) and c["type"] != "link":
                problems += 1
                desc = "%o %d:%d -> %o %d:%d" % (e["mode"], e["uid"], e["gid"], c["mode"], c["uid"], c["gid"])
                if enforce:
                    try:
                        os.chmod(p, e["mode"])
                        os.chown(p, e["uid"], e["gid"])
                        log("ALERT", "PERMS changed and reset: %s (%s)" % (p, desc))
                    except OSError as ex:
                        log("ALERT", "PERMS changed: %s (%s) - reset failed: %s" % (p, desc, ex))
                else:
                    log("ALERT", "PERMS changed: %s (%s)" % (p, desc))
        # DELETED
        for rel in sorted(set(base_files) - set(cur)):
            if rel.endswith(".pyc"):
                continue                    # python can regenerate it
            p = p_of(rel)
            problems += 1
            if enforce:
                try:
                    restore(p, base_files[rel])
                    log("ALERT", "DELETED file restored: %s" % p)
                except Exception as ex:
                    log("ALERT", "DELETED file %s - RESTORE FAILED: %s" % (p, ex))
            else:
                log("ALERT", "DELETED file: %s" % p)
    if problems == 0 and not quiet_ok:
        log("OK", "integrity OK (%d files)" % sum(len(v) for v in b["files"].values()))
    return problems


def cmd_check(args):
    b = load_baseline()
    sys.exit(1 if one_pass(b, enforce=False) else 0)


def cmd_watch(args):
    b = load_baseline()
    enforce = not args.report_only
    log("INFO", "watching %s (%s) every %ss - mode: %s" % (
        b["target"].get("container") or b["target"].get("app"), b["target"]["kind"],
        args.interval, "ENFORCE (quarantine + restore)" if enforce else "report only"))
    one_pass(b, enforce)
    last_ok = time.time()
    while True:
        time.sleep(args.interval)
        if one_pass(b, enforce, quiet_ok=True) == 0 and time.time() - last_ok > 300:
            log("OK", "still clean")      # heartbeat every ~5 min so you know it's alive
            last_ok = time.time()


def cmd_update(args):
    b = load_baseline()
    roots = resolve_roots(b["target"])
    snap, paths = scan(roots, b.get("ignore", []))
    if args.path:
        want = set(os.path.normpath(w) for w in args.path)
        merged = ""
        if b["target"]["kind"] == "docker":
            merged = (docker_json(b["target"]["container"]) or {}).get("GraphDriver", {}).get("Data", {}).get("MergedDir", "")

        def names(label, rel):
            p = os.path.join(paths[label], rel) if rel else paths[label]
            n = {os.path.normpath(p)}
            if merged and p.startswith(merged):
                n.add(os.path.normpath(p[len(merged):]))      # in-container path, e.g. /pinry/core/views.py
            if label == "local_settings":
                n.add("/data/local_settings.py")
            return p, n
        hit = 0
        for label in set(snap) | set(b["files"]):
            if label not in paths:
                continue
            for rel in set(snap.get(label, {})) | set(b["files"].get(label, {})):
                p, n = names(label, rel)
                if not (n & want):
                    continue
                if rel in snap.get(label, {}):
                    store_copy(p, snap[label][rel])
                    b["files"].setdefault(label, {})[rel] = snap[label][rel]
                    log("OK", "accepted into baseline: %s" % p)
                else:
                    del b["files"][label][rel]
                    log("OK", "removed from baseline (file gone): %s" % p)
                hit += 1
        if not hit:
            die("none of those paths are in a watched area (use the full path)")
    else:
        for label, files in snap.items():
            for rel, e in files.items():
                store_copy(os.path.join(paths[label], rel) if rel else paths[label], e)
        b["files"] = snap
        log("OK", "full re-baseline: %d files" % sum(len(v) for v in snap.values()))
    save_baseline(b)


def cmd_status(args):
    b = load_baseline()
    t = b["target"]
    print("target   : %s %s" % (t["kind"], t.get("container") or t.get("app")))
    print("baseline : %s (%d files)" % (time.ctime(b["created"]), sum(len(v) for v in b["files"].values())))
    for label, files in b["files"].items():
        print("  %-40s %5d" % (label, len(files)))
    idx = os.path.join(QUAR, "INDEX.log")
    if os.path.isfile(idx):
        lines = open(idx).read().splitlines()
        print("quarantine: %d item(s) - last 10:" % len(lines))
        for l in lines[-10:]:
            print("  " + l)
    else:
        print("quarantine: empty")


def main():
    if os.geteuid() != 0:
        print("run as root (sudo)", file=sys.stderr)
        sys.exit(1)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="create the baseline (do this right after hardening)")
    p.add_argument("--docker", metavar="CONTAINER")
    p.add_argument("--app-in-container", default="/pinry")
    p.add_argument("--app", metavar="PATH", help="bare-metal Pinry base folder")
    p.add_argument("--python", default="python3", help="bare metal: the python that runs Pinry (venv)")
    p.add_argument("--site-packages", action="append", help="override site-packages dir(s)")
    p.add_argument("--ignore", action="append", default=[], help="glob relative to a watched dir, e.g. 'logs/*'")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("check", help="single pass, report only (exit 1 if anything changed)")
    p.set_defaults(fn=cmd_check)
    p = sub.add_parser("watch", help="enforce continuously")
    p.add_argument("--interval", type=float, default=10)
    p.add_argument("--report-only", action="store_true", help="alert but don't quarantine/restore")
    p.set_defaults(fn=cmd_watch)
    p = sub.add_parser("update", help="re-baseline (after YOUR intentional changes)")
    p.add_argument("--path", action="append", help="accept only this file (repeatable)")
    p.set_defaults(fn=cmd_update)
    p = sub.add_parser("status", help="show baseline + recent quarantine")
    p.set_defaults(fn=cmd_status)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
