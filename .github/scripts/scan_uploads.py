#!/usr/bin/env python3
"""
Scans, re-encodes and releases (or rejects) uploaded images held in the private
R2 bucket. Fails closed: nothing is released unless it was scanned.

Silent on purpose. This repository is public, and so are its Actions logs and
run history, so the script prints nothing about files, counts or errors. The
exit code is the only signal (0 = fine, 1 = something needs a look).

Usage:
  scan_uploads.py            process the bucket
  scan_uploads.py --local D  same, against a local directory (tests)

Environment:
  R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET
  SCAN_CMD  scanner command, default "clamscan" (exit 0 clean, 1 infected, else error)
  VT_API_KEY  optional: also look up each file's SHA-256 on VirusTotal (hash only,
              the file is never uploaded); known-malicious files are rejected
"""
import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

MAX_BYTES = int(1.5 * 1024 * 1024)  # same limit as the Worker
CHUNK = 150  # files per scanner run (bounds memory; one signature load per chunk)
WORKERS = 8  # parallel downloads / re-encodes / uploads

# VirusTotal, hash lookups only. The free public API allows 4 lookups a minute and
# 500 a day; this is an extra signal on top of ClamAV, so any failure (quota,
# network, unknown hash) simply means "no opinion" and never blocks a release.
VT_URL = "https://www.virustotal.com/api/v3/files/"
VT_INTERVAL = 15.5  # seconds between lookups (4 per minute)
VT_MAX_PER_RUN = 30  # keeps one run well inside the job timeout
VT_MIN_DETECTIONS = 2  # engines that must call it malicious (avoids single-engine false positives)
MAX_PIXELS = 40_000_000
KEY_RE = re.compile(
    r"^quarantine/(MVR-GDBOP-\d{8}-[A-Z2-9]{5})/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(png|jpg|webp)$"
)
FORMATS = {"png": "PNG", "jpg": "JPEG", "webp": "WEBP"}
MIME = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp"}


def detect(data: bytes) -> str:
    """Image type from the leading bytes ('' if not png/jpg/webp)."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return ""


def reencode(data: bytes, kind: str) -> bytes:
    """Decode and rebuild the image from raw pixels so no metadata or trailing data survives."""
    from PIL import Image, ImageOps

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    with Image.open(io.BytesIO(data), formats=[FORMATS[kind]]) as im:
        if im.width * im.height > MAX_PIXELS:
            raise ValueError("too many pixels")
        im.load()
        im = ImageOps.exif_transpose(im)  # honour rotation, then forget the EXIF
        has_alpha = "A" in im.getbands() or im.info.get("transparency") is not None
        mode = "RGBA" if has_alpha and kind != "jpg" else "RGB"
        im = im.convert(mode)
        fresh = Image.frombytes(mode, im.size, im.tobytes())
    out = io.BytesIO()
    if kind == "png":
        fresh.save(out, "PNG", optimize=True)
    elif kind == "jpg":
        fresh.save(out, "JPEG", quality=90, optimize=True)
    else:
        fresh.save(out, "WEBP", quality=90)
    return out.getvalue()


def scan_batch(blobs, scan_cmd):
    """Scan many files with ONE scanner process (the signature database is loaded once).

    `blobs` maps a caller key to bytes; returns the same keys mapped to
    'clean' | 'infected' | 'error'. Files get random names in a temp dir. Exit code
    0 = all clean, 1 = infected (the scanner names them; if it names none, every
    file in the batch is treated as infected), anything else = error for all.
    """
    if not blobs:
        return {}
    with tempfile.TemporaryDirectory() as tmp:
        names = {}
        for key, data in blobs.items():
            name = uuid.uuid4().hex + ".bin"
            names[name] = key
            with open(os.path.join(tmp, name), "wb") as fh:
                fh.write(data)
        try:
            proc = subprocess.run(
                [*shlex.split(scan_cmd), "-r", "--no-summary", tmp],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=900, text=True, errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired):
            return {key: "error" for key in blobs}
    if proc.returncode == 0:
        return {key: "clean" for key in blobs}
    if proc.returncode == 1:
        found = set()
        for line in proc.stdout.splitlines():
            if line.endswith(" FOUND") and ": " in line:
                found.add(os.path.basename(line[: line.rindex(": ")]))
        infected = {names[n] for n in found if n in names} or set(blobs)
        return {key: ("infected" if key in infected else "clean") for key in blobs}
    return {key: "error" for key in blobs}


def scan(data: bytes, scan_cmd: str) -> str:
    """Single-file convenience wrapper around scan_batch."""
    return scan_batch({"x": data}, scan_cmd)["x"]


class S3Store:
    def __init__(self):
        import boto3
        from botocore.config import Config

        self.bucket = os.environ["R2_BUCKET"]
        self.s3 = boto3.client(
            "s3",
            endpoint_url=f"https://{os.environ['R2_ACCOUNT_ID']}.r2.cloudflarestorage.com",
            aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
            region_name="auto",
            config=Config(signature_version="s3v4", retries={"max_attempts": 3}),
        )

    def list(self, prefix):
        for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                yield obj["Key"]

    def get(self, key):
        return self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def put(self, key, body, content_type):
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType=content_type)

    def delete(self, key):
        self.s3.delete_object(Bucket=self.bucket, Key=key)


class DirStore:
    """Same interface over a directory, for tests."""

    def __init__(self, root):
        self.root = root

    def _p(self, key):
        return os.path.join(self.root, *key.split("/"))

    def list(self, prefix):
        for dirpath, _, names in os.walk(self.root):
            for n in names:
                key = os.path.relpath(os.path.join(dirpath, n), self.root).replace(os.sep, "/")
                if key.startswith(prefix):
                    yield key

    def get(self, key):
        with open(self._p(key), "rb") as fh:
            return fh.read()

    def put(self, key, body, content_type):
        os.makedirs(os.path.dirname(self._p(key)), exist_ok=True)
        with open(self._p(key), "wb") as fh:
            fh.write(body)

    def delete(self, key):
        os.remove(self._p(key))


def _vt_get(sha256, api_key):
    """JSON for a hash VirusTotal knows, None if it does not. Raises otherwise.

    Only the hash goes out: a GET with no body.
    """
    req = urllib.request.Request(VT_URL + sha256, headers={"x-apikey": api_key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        err.close()
        if err.code == 404:
            return None
        raise


def vt_verdicts(blobs, api_key, sleep=time.sleep):
    """Maps each key to 'malicious' | 'known-clean' | 'unknown' using hash lookups."""
    out = {key: "unknown" for key in blobs}
    if not api_key:
        return out
    for i, (key, data) in enumerate(blobs.items()):
        if i >= VT_MAX_PER_RUN:
            break
        if i:
            sleep(VT_INTERVAL)
        try:
            info = _vt_get(hashlib.sha256(data).hexdigest(), api_key)
        except urllib.error.HTTPError as err:
            err.close()
            if err.code in (401, 403, 429):  # bad key or quota used up: stop asking this run
                break
            continue
        except Exception:
            continue
        if info is None:
            continue
        stats = (info.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
        try:
            malicious = int(stats.get("malicious", 0) or 0)
        except (TypeError, ValueError):
            malicious = 0
        out[key] = "malicious" if malicious >= VT_MIN_DETECTIONS else "known-clean"
    return out


def _chunks(items, n):
    for i in range(0, len(items), n):
        yield items[i : i + n]


def process(store, scan_cmd="clamscan", vt_key=None, sleep=time.sleep):
    counts = {"clean": 0, "rejected": 0, "ignored": 0, "errors": 0}
    pending = []  # (key, report_id, name, ext)
    for key in list(store.list("quarantine/")):
        if key.endswith("/_sent"):  # marker the Worker may leave next to a report's files
            continue
        m = KEY_RE.match(key)
        if not m:  # the Worker never writes such keys
            store.delete(key)
            counts["ignored"] += 1
            continue
        report_id, stem, ext = m.groups()
        pending.append((key, report_id, f"{stem}.{ext}", ext))

    def reject(item, reason):
        key, report_id, name, _ = item
        store.put(f"rejected/{report_id}/{name}", reason.encode(), "text/plain")
        store.delete(key)

    def fetch(item):
        try:
            return store.get(item[0])
        except Exception:
            return None

    def release(args):
        item, data = args
        key, report_id, name, ext = item
        try:
            clean = reencode(data, ext)
        except Exception:
            return item, False
        store.put(f"clean/{report_id}/{name}", clean, MIME[ext])
        store.delete(key)
        return item, True

    with ThreadPoolExecutor(WORKERS) as pool:
        for chunk in _chunks(pending, CHUNK):
            blobs = {}
            for item, data in zip(chunk, pool.map(fetch, chunk)):
                if data is None:  # vanished or unreadable: try again next run
                    counts["errors"] += 1
                elif len(data) > MAX_BYTES:
                    reject(item, "too_large"); counts["rejected"] += 1
                elif detect(data) != item[3]:
                    reject(item, "invalid"); counts["rejected"] += 1
                else:
                    blobs[item[0]] = (item, data)
            verdicts = scan_batch({k: v[1] for k, v in blobs.items()}, scan_cmd)
            passed = {}
            for key, (item, data) in blobs.items():
                verdict = verdicts[key]
                if verdict == "infected":
                    reject(item, "infected"); counts["rejected"] += 1
                elif verdict == "error":
                    counts["errors"] += 1  # stays in quarantine, retried next run
                else:
                    passed[key] = (item, data)
            # second opinion on what ClamAV let through: hash lookup of the original file
            vt = vt_verdicts({k: v[1] for k, v in passed.items()}, vt_key, sleep)
            to_release = []
            for key, (item, data) in passed.items():
                if vt[key] == "malicious":
                    reject(item, "infected"); counts["rejected"] += 1
                else:
                    to_release.append((item, data))
            for item, ok in pool.map(release, to_release):
                if ok:
                    counts["clean"] += 1
                else:
                    reject(item, "invalid"); counts["rejected"] += 1
    return counts


def main(argv):
    local = argv[argv.index("--local") + 1] if "--local" in argv else None
    store = DirStore(local) if local else S3Store()
    counts = process(store, os.environ.get("SCAN_CMD", "clamscan"), os.environ.get("VT_API_KEY") or None)
    return 1 if counts["errors"] else 0


if __name__ == "__main__":
    try:
        code = main(sys.argv[1:])
    except BaseException:
        # No traceback or message: a library error could echo bucket or object
        # names into a public log. The failed run itself is the signal.
        code = 1
    sys.exit(code)
