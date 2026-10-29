import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, TimeoutError, wait
from importlib.metadata import version
from pathlib import Path

from pebble import ProcessExpired, ProcessPool

from . import db, ocr, worker
from .rules import Rules
from .safety import describe

DONE = {"ok", "encrypted", "unsupported", "corrupt", "too_large"}
TMP_PREFIX = "piiscan-run-"
STALE_TMP_SECONDS = 24 * 3600
PKG_DIR = Path(__file__).resolve().parent
READERS = ["detect.py", "worker.py", "model.py", "sniff.py", "extract", "ocr"]
GPU_WORKERS = 4


def default_workers() -> int:
    cores = max(1, (os.cpu_count() or 2) - 1)
    return min(cores, GPU_WORKERS) if ocr.device().type != "cpu" else cores


def scanner_version(rules: Rules | None) -> str:
    h = hashlib.sha256()
    files = [PKG_DIR / r for r in READERS if r.endswith(".py")]
    files += [p for r in READERS if not r.endswith(".py") for p in (PKG_DIR / r).rglob("*.py")]
    for p in sorted(files):
        h.update(p.relative_to(PKG_DIR).as_posix().encode() + b"\0" + p.read_bytes())
    h.update(json.dumps(sorted((t["code"], t["words"]) for t in rules.types) if rules else []).encode())
    card = ocr.MODELS_DIR / "handwriting" / "model_card.json"
    h.update(card.read_bytes() if card.exists() else b"")
    return h.hexdigest()[:16]


def run(root: Path, db_path: Path, key: bytes, workers: int, timeout: int, full: bool = False,
        rules: Rules | None = None, changed_only: bool = False, say=lambda *_: None) -> Counter:
    if not ocr.models_ready():
        raise SystemExit("piiscan: OCR models are missing; run `uv run scripts/setup.py` (downloads happen only there)")
    root = root.absolute()
    prefix = os.path.join(str(root), "")
    current = scanner_version(rules)
    config = {"root": str(root), "workers": workers, "timeout": timeout, "full": full, "scanner": current,
              "changed_only": changed_only}
    db_path.absolute().parent.mkdir(parents=True, exist_ok=True)
    lock = _lock(db_path.with_name(db_path.name + ".lock"))
    if lock is None:
        raise SystemExit("piiscan: another scan is running against this DB; wait for it to finish")
    con = db.connect(db_path)
    try:
        run_id = db.start_run(con, str(root), config, hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
                              version("piiscan"), True)
        _sweep_stale_tmp()
        tmpdir = Path(tempfile.mkdtemp(prefix=f"{TMP_PREFIX}{run_id}-"))
        counts: Counter = Counter()
        status = "failed"
        try:
            known = db.known_files(con, prefix)
            fresh = lambda k: changed_only or k[5] == current
            stale = sum(k[4] in DONE and not fresh(k) for k in known.values())
            if stale and not full:
                say(f"{stale} file(s) were read by an older version of the scanner or before your types changed; "
                    "re-reading them so the database matches (add --changed-only to skip this).")
            skip_dirs = {db_path.absolute().parent, tmpdir}
            threads = max(1, (os.cpu_count() or 1) // workers)
            with ProcessPool(max_workers=workers, max_tasks=200, initializer=worker.init,
                             initargs=(key, str(tmpdir), True, threads, rules.data() if rules else None)) as pool:
                pending: dict = {}
                for path, st in walk(root, skip_dirs, counts):
                    k = known.get(str(path))
                    same = bool(k) and k[1] == st.st_size and k[2] == st.st_mtime_ns and k[4] in DONE
                    if not full and same and fresh(k):
                        db.record_unchanged(con, run_id, k[0], str(path), st.st_size, st.st_mtime_ns)
                        counts["unchanged"] += 1
                        continue
                    if not full and same:
                        counts["re-read for scanner update"] += 1
                    known_sha = k[3] if k and not full and k[4] in DONE and fresh(k) else None
                    fut = pool.schedule(worker.process, args=(str(path), known_sha),
                                        timeout=timeout + st.st_size // (512 * 1024))
                    pending[fut] = (path, st)
                    if len(pending) >= workers * 4:
                        _drain(pending, con, run_id, root, counts, FIRST_COMPLETED, current)
                _drain(pending, con, run_id, root, counts, None, current)
            counts["missing"] = db.mark_missing(con, run_id, prefix)
            if rules is not None:
                counts["bypassed"] = db.apply_bypass(con, rules.hmacs(key))["bypassed"]
            status = "completed"
        except KeyboardInterrupt:
            status = "aborted"
            raise
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
            db.finish_run(con, run_id, status, dict(counts))
    finally:
        con.close()
        lock.close()
    return counts


def _lock(path: Path):
    try:
        f = open(path, "a+b")
    except OSError:
        return None
    try:
        if sys.platform == "win32":
            import msvcrt

            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


def walk(root: Path, skip_dirs: set, counts: Counter):
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: counts.update(["dir_errors"])):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if (here / d).absolute() not in skip_dirs)
        for name in sorted(filenames):
            p = here / name
            try:
                st = p.stat(follow_symlinks=False)
            except OSError:
                counts["stat_errors"] += 1
                continue
            if stat.S_ISREG(st.st_mode):
                yield p, st


def _drain(pending: dict, con, run_id: int, root: Path, counts: Counter, until, scanner: str) -> None:
    done, _ = wait(pending, return_when=until) if until else (list(pending), None)
    for fut in done:
        path, st = pending.pop(fut)
        try:
            result = fut.result()
        except TimeoutError:
            result = _failed("timeout", None)
        except ProcessExpired as e:
            result = _failed("error", f"worker exited {e.exitcode}")
        except Exception as e:
            result = _failed("error", describe(e))
        rel = path.relative_to(root).parts
        area = rel[0] if len(rel) > 1 else "(root)"
        db.write_result(con, run_id, str(path), area, st.st_size, st.st_mtime_ns, result, scanner)
        for rec in result["records"]:
            counts[rec["status"]] += 1
            counts.update(f"found:{f['pii_type']}" for f in rec["findings"])


def _failed(status: str, error: str | None) -> dict:
    return {"sha256": None, "owner": None, "duration_ms": None,
            "records": [{"member": None, "type": None, "status": status, "error": error, "pages": 0, "ocr_pages": 0,
                         "rotated_pages": 0, "findings": []}]}


def _sweep_stale_tmp() -> None:
    cutoff = time.time() - STALE_TMP_SECONDS
    for p in Path(tempfile.gettempdir()).glob(f"{TMP_PREFIX}*"):
        try:
            if p.stat().st_mtime < cutoff:
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            pass
