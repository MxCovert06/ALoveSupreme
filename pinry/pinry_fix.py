#!/usr/bin/env python3
"""pinry_fix.py - patch Pinry: SSRF + unsafe filename + shared-image delete (core/models.py),
stored XSS + foreign image attach (core/serializers.py), login brute force (users/views.py).

    python3 pinry_fix.py /pinry            # base folder = the dir containing manage.py
    python3 pinry_fix.py /pinry --dry-run  # check only, change nothing

All-or-nothing: every edit is verified before any file is written. Originals are saved
as <file>.bak-<timestamp>. Safe to re-run (already-patched files are skipped).
Docker:  docker cp pinry_fix.py <c>:/tmp/ && docker exec <c> python3 /tmp/pinry_fix.py /pinry
"""
import argparse
import os
import py_compile
import shutil
import sys
import tempfile
import time

MARK = "# CCDC-PATCHED"

# ---------------------------------------------------------------- core/models.py
MODELS = [
    ("imports",
     "import PIL.Image\nimport requests\n",
     MARK + "\nimport ipaddress\nimport socket\nfrom urllib.parse import urlparse, urljoin\n\n"
     "import PIL.Image\nimport requests\n"),

    ("create_for_url: SSRF + remote filename",
     """    # FIXME: Move this into an asynchronous task
    def create_for_url(self, url, referer=None):
        file_name = url.split("/")[-1].split('#')[0].split('?')[0]
        buf = BytesIO()
        headers = dict(self._default_ua)
        if referer is not None:
            headers["Referer"] = referer
        response = requests.get(url, headers=headers)
        buf.write(response.content)
        if not self._is_valid_image(buf):
            return None
        obj = InMemoryUploadedFile(buf, 'image', file_name,
                                   None, buf.tell(), None)
""",
     """    _MAX_BYTES = 10 * 1024 * 1024
    _MAX_REDIRECTS = 3
    _EXT_BY_FORMAT = {'JPEG': 'jpg', 'PNG': 'png', 'GIF': 'gif',
                      'WEBP': 'webp', 'BMP': 'bmp'}

    @staticmethod
    def _assert_public_url(url):
        # only http(s) to public addresses (blocks SSRF to internal hosts/metadata)
        p = urlparse(url)
        if p.scheme not in ('http', 'https') or not p.hostname:
            raise ValueError('bad scheme/host')
        # escape hatch for the scoring engine: PIN_FETCH_ALLOW_HOSTS = ['10.x.x.x']
        if p.hostname in getattr(settings, 'PIN_FETCH_ALLOW_HOSTS', []):
            return
        port = p.port or (443 if p.scheme == 'https' else 80)
        for info in socket.getaddrinfo(p.hostname, port, proto=socket.IPPROTO_TCP):
            ip = ipaddress.ip_address(info[4][0].split('%')[0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local or
                    ip.is_multicast or ip.is_reserved or ip.is_unspecified):
                raise ValueError('internal address blocked: %s' % ip)

    def _safe_get(self, url, headers):
        # re-validate every redirect hop, timeout, size cap
        for _ in range(self._MAX_REDIRECTS + 1):
            self._assert_public_url(url)
            r = requests.get(url, headers=headers, timeout=(5, 10),
                             allow_redirects=False, stream=True)
            if r.is_redirect:
                url = urljoin(url, r.headers.get('location', ''))
                r.close()
                continue
            buf = BytesIO()
            for chunk in r.iter_content(64 * 1024):
                buf.write(chunk)
                if buf.tell() > self._MAX_BYTES:
                    r.close()
                    raise ValueError('remote image too large')
            r.close()
            return buf
        raise ValueError('too many redirects')

    # FIXME: Move this into an asynchronous task
    def create_for_url(self, url, referer=None):
        headers = dict(self._default_ua)
        if referer is not None:
            headers["Referer"] = referer
        try:
            buf = self._safe_get(url, headers)
        except (ValueError, OSError, requests.RequestException):
            return None
        if not self._is_valid_image(buf):
            return None
        # never trust the remote filename/extension (x.html polyglots)
        try:
            fmt = PIL.Image.open(buf).format
        except Exception:
            return None
        buf.seek(0, 2)
        ext = self._EXT_BY_FORMAT.get(fmt)
        if ext is None:
            return None
        obj = InMemoryUploadedFile(buf, 'image', 'remote.' + ext,
                                   None, buf.tell(), None)
"""),

    ("delete_pin_images: shared-image cascade delete",
     """def delete_pin_images(sender, instance, **kwargs):
    try:
        instance.image.delete()
    except Image.DoesNotExist:
        pass""",
     """def delete_pin_images(sender, instance, **kwargs):
    try:
        image = instance.image
    except Image.DoesNotExist:
        return
    # only delete the image if no OTHER pin still uses it
    if Pin.objects.filter(image_id=image.pk).exclude(pk=instance.pk).exists():
        return
    image.delete()"""),
]

# ---------------------------------------------------------------- core/serializers.py
SERIALIZERS = [
    ("imports",
     "from django.conf import settings\n",
     MARK + "\nfrom urllib.parse import urlparse\n\nfrom django.conf import settings\n"),

    ("PinSerializer validators: javascript: URLs, quote injection, foreign image_by_id",
     """    def create(self, validated_data):
        if 'url' not in validated_data and\\
""",
     """    @staticmethod
    def _http_only(value):
        # block javascript:/data: links (rendered as <a :href> in the SPA)
        if value and urlparse(value.strip()).scheme.lower() not in ('http', 'https'):
            raise ValidationError("only http(s) URLs are allowed")
        return value.strip() if value else value

    def validate_url(self, value):
        return self._http_only(value)

    def validate_referer(self, value):
        return self._http_only(value)

    def validate_description(self, value):
        # SPA niceLinks() doesn't escape quotes -> attribute-injection XSS
        if value:
            value = value.replace('"', '').replace('`', '')
        return value

    def validate_image_by_id(self, image):
        # can't attach (and later delete) another user's image
        user = self.context['request'].user
        if image.pin.exclude(submitter=user).exists():
            raise ValidationError("image belongs to another user")
        return image

    def create(self, validated_data):
        if 'url' not in validated_data and\\
"""),
]

# ---------------------------------------------------------------- users/views.py
VIEWS = [
    ("imports",
     "from django.conf import settings\n",
     MARK + "\nfrom django.conf import settings\nfrom django.core.cache import cache\n"),

    ("login_user: brute-force lockout",
     """    user = authenticate(
        request,
        username=data['username'],
        password=data['password']
    )
    if not user:
        return HttpResponseBadRequest(
            json.dumps({"password": "username and password doesn't match"})
        )
""",
     """    # lockout: 10 failures per source IP per 5 min (per-IP on purpose, so
    # red team can't lock out the scoring account by username)
    ip = request.META.get('REMOTE_ADDR', '')
    if ip in ('127.0.0.1', '::1'):  # behind local nginx: trust X-Real-IP
        ip = request.META.get('HTTP_X_REAL_IP', ip)
    lock_key = 'ccdc-login-ip:%s' % ip
    if cache.get(lock_key, 0) >= 10:
        return HttpResponse(json.dumps({"password": "too many attempts, try later"}),
                            status=429, content_type="application/json")
    user = authenticate(
        request,
        username=data['username'],
        password=data['password']
    )
    if not user:
        cache.add(lock_key, 0, 300)
        try:
            cache.incr(lock_key)
        except ValueError:
            cache.set(lock_key, 1, 300)
        return HttpResponseBadRequest(
            json.dumps({"password": "username and password doesn't match"})
        )
"""),
]

TARGETS = [
    ("core/models.py", MODELS),
    ("core/serializers.py", SERIALIZERS),
    ("users/views.py", VIEWS),
]


class PatchError(Exception):
    pass


def main():
    ap = argparse.ArgumentParser(description="Patch Pinry core/models.py, core/serializers.py, users/views.py")
    ap.add_argument("base", help="Pinry base folder (the one containing manage.py)")
    ap.add_argument("--dry-run", action="store_true", help="verify only, write nothing")
    args = ap.parse_args()

    base = os.path.abspath(args.base)
    if not os.path.isdir(base):
        raise PatchError("base folder not found: %s" % base)
    missing = [f for f in ["manage.py"] + [t for t, _ in TARGETS]
               if not os.path.isfile(os.path.join(base, f))]
    if missing:
        raise PatchError("%s doesn't look like a Pinry base folder - missing: %s"
                         % (base, ", ".join(missing)))

    # pass 1: build every new file in memory, fail before touching disk
    planned = []
    for rel, edits in TARGETS:
        path = os.path.join(base, rel)
        with open(path, encoding="utf-8") as f:
            src = f.read()
        if MARK in src:
            print("[=] already patched, skipping: %s" % rel)
            continue
        new = src
        for name, old, repl in edits:
            n = new.count(old)
            if n != 1:
                raise PatchError(
                    "%s: can't apply '%s' - expected code found %d times (need exactly 1).\n"
                    "    The file differs from upstream Pinry (different version, or TAMPERED).\n"
                    "    Nothing was changed. Diff it against the original source by hand."
                    % (rel, name, n))
            new = new.replace(old, repl, 1)
        # make sure the result is valid Python before we write it
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tmp:
            tmp.write(new)
        try:
            py_compile.compile(tmp.name, doraise=True)
        except py_compile.PyCompileError as e:
            raise PatchError("%s: patched result doesn't compile: %s" % (rel, e))
        finally:
            os.unlink(tmp.name)
        planned.append((rel, path, new, [e[0] for e in edits]))

    if not planned:
        print("[+] nothing to do - all files already patched")
        return 0
    if args.dry_run:
        for rel, _, _, names in planned:
            print("[*] would patch %s: %s" % (rel, "; ".join(names)))
        print("[*] dry run - no files changed")
        return 0

    # pass 2: backup + write
    ts = time.strftime("%Y%m%d_%H%M%S")
    for rel, path, new, names in planned:
        shutil.copy2(path, "%s.bak-%s" % (path, ts))
        st = os.stat(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(new)
        try:
            os.chown(path, st.st_uid, st.st_gid)
        except (PermissionError, AttributeError):
            pass
        print("[+] patched %s: %s" % (rel, "; ".join(names)))
        print("    backup: %s.bak-%s" % (rel, ts))

    print("\nNext: python manage.py check  ->  restart the app (docker restart <container> / restart gunicorn)")
    print("Rollback: copy each .bak-%s file back over the original and restart." % ts)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PatchError as e:
        print("[x] ERROR: %s" % e, file=sys.stderr)
        sys.exit(1)
