import hashlib
import io
import logging
import os
import sys
import tempfile
import time
import warnings
from pathlib import Path

from PIL import Image as PILImage

from .detect import detect, value_hmac
from .extract import EXTRACTORS
from .model import Child, Encrypted, Image, Span, TooLarge, Unsupported
from .ocr.engine import read_page
from .safety import describe, is_our_bug
from .sniff import sniff

MAX_INMEM = 256 << 20
MAX_DEPTH = 5
ROTATION_MIN = 1.0
_key: bytes = b""


def init(key: bytes, tmpdir: str | None = None, quiet: bool = True, threads: int | None = None) -> None:
    global _key
    _key = key
    if threads:
        os.environ["OMP_NUM_THREADS"] = str(threads)
    if tmpdir:
        tempfile.tempdir = tmpdir
    if quiet:
        warnings.simplefilter("ignore")
        logging.disable(logging.CRITICAL)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        sys.stdout = sys.stderr = open(os.devnull, "w")


def process(path: str, known_sha256: str | None) -> dict:
    started = time.monotonic()
    p = Path(path)
    records: list[dict] = []
    sha = None
    try:
        with open(p, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            h = hashlib.sha256()
            if size <= MAX_INMEM:
                data = f.read()
                h.update(data)
                src = io.BytesIO(data)
            else:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
                f.seek(0)
                src = f
            sha = h.hexdigest()
            if sha == known_sha256:
                return {"sha256": sha, "owner": None, "duration_ms": _ms(started), "records": [_record(None, "unchanged")]}
            scan_blob(src, p.name, None, 0, records)
    except OSError as e:
        records = [_record(None, "error", error=describe(e))]
    return {"sha256": sha, "owner": owner(p), "duration_ms": _ms(started), "records": records}


def scan_blob(f, name: str, member: str | None, depth: int, out: list[dict]) -> None:
    rec = _record(member, "ok")
    out.append(rec)
    try:
        kind = sniff(f.read(8192), name, f)
        f.seek(0)
        rec["type"] = kind
        if kind == "encrypted_ooxml":
            raise Encrypted
        if kind == "unsupported":
            raise Unsupported
        for item in EXTRACTORS[kind](f, name):
            if isinstance(item, Span):
                rec["pages"] = max(rec["pages"], item.page or 0)
                rec["findings"].extend(_findings(item))
            elif isinstance(item, Image):
                rec["pages"] = max(rec["pages"], item.page or 0)
                rec["ocr_pages"] += 1
                angle, spans = read_page(item.load(), item.page)
                if abs(angle) >= ROTATION_MIN:
                    rec["rotated_pages"] += 1
                rec["findings"].extend(_one_per_reading([f for span in spans for f in _findings(span)]))
            elif isinstance(item, Child):
                child = _join(member, item.name)
                if item.status:
                    out.append(_record(child, item.status))
                elif depth >= MAX_DEPTH:
                    out.append(_record(child, "too_large"))
                else:
                    scan_blob(io.BytesIO(item.data), item.name, child, depth + 1, out)
    except Encrypted:
        rec["status"] = "encrypted"
    except Unsupported:
        rec["status"] = "unsupported"
    except (TooLarge, PILImage.DecompressionBombError):
        rec["status"] = "too_large"
    except Exception as e:
        rec["status"] = "error" if is_our_bug(e) else "corrupt"
        rec["error"] = describe(e)


def _findings(span: Span) -> list[dict]:
    out = []
    for pii_type, start, end, normalized, conf, method in detect(span.text, span.header):
        where = span.where(start, end) if span.where else (None, None)
        locator, bbox = where[0], where[1]
        if len(where) > 2:
            conf *= 0.5 + 0.5 * where[2]
        if span.source != "text_layer":
            method += f"+{span.source}"
        if locator is None:
            line = f"L{span.line0 + span.text.count(chr(10), 0, start)}"
            multiline = "\n" in span.text or span.line0 > 1
            locator = (f"{span.locator}:{line}" if multiline else span.locator) if span.locator else line
        out.append({
            "page": span.page, "locator": locator, "bbox": bbox, "pii_type": pii_type,
            "value_hmac": value_hmac(_key, pii_type, normalized),
            "confidence": round(conf * span.conf, 3), "method": method,
        })
    return out


def _one_per_reading(findings: list[dict]) -> list[dict]:
    kept: list[dict] = []
    for f in sorted(findings, key=lambda f: (not f["method"].endswith("+ocr_hand"), -f["confidence"])):
        if not any(g["pii_type"] == f["pii_type"] and g["method"].rsplit("+", 1)[-1] != f["method"].rsplit("+", 1)[-1]
                   and _overlap(g["bbox"], f["bbox"]) for g in kept):
            kept.append(f)
    return kept


def _overlap(a, b) -> bool:
    return bool(a and b) and a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def _record(member, status, error=None) -> dict:
    return {"member": member, "type": None, "status": status, "error": error, "pages": 0, "ocr_pages": 0,
            "rotated_pages": 0, "findings": []}


def _join(parent: str | None, name: str) -> str:
    return f"{parent}!/{name}" if parent else name


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def owner(p: Path) -> str | None:
    if sys.platform != "win32":
        return None
    try:
        import win32security

        sd = win32security.GetFileSecurity(str(p), win32security.OWNER_SECURITY_INFORMATION)
        name, domain, _ = win32security.LookupAccountSid(None, sd.GetSecurityDescriptorOwner())
        return f"{domain}\\{name}"
    except Exception:
        return None
