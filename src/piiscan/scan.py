import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, TimeoutError, wait
from importlib.metadata import version
from pathlib import Path

from pebble import ProcessExpired, ProcessPool

from . import db, ocr, worker
from .safety import describe

DONE = {"ok", "encrypted", "unsupported", "corrupt", "too_large"}
TMP_PREFIX = "piiscan-run-"
STALE_TMP_SECONDS = 24 * 3600


def run(root: Path, db_path: Path, key: bytes, workers: int, timeout: int, full: bool = False, force: bool = False) -> Counter:
    if not ocr.models_ready():
        raise SystemExit("piiscan: OCR models are missing; run `uv run scripts/setup.py` (downloads happen only there)")
    root = root.absolute()
    prefix = os.path.join(str(root), "")
    config = {"root": str(root), "workers": workers, "timeout": timeout, "full": full}
    con = db.connect(db_path)
    run_id = db.start_run(con, str(root), config, hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
                          version("piiscan"), force)
    _sweep_stale_tmp()
    tmpdir = Path(tempfile.mkdtemp(prefix=f"{TMP_PREFIX}{run_id}-"))
    counts: Counter = Counter()
    status = "failed"
    try:
        known = db.known_files(con, prefix)
        skip_dirs = {db_path.absolute().parent, tmpdir}
        threads = max(1, (os.cpu_count() or 1) // workers)
        with ProcessPool(max_workers=workers, max_tasks=200, initializer=worker.init,
                         initargs=(key, str(tmpdir), True, threads)) as pool:
            pending: dict = {}
            for path, st in walk(root, skip_dirs, counts):
                k = known.get(str(path))
                if not full and k and k[1] == st.st_size and k[2] == st.st_mtime_ns and k[4] in DONE:
                    db.record_unchanged(con, run_id, k[0], str(path), st.st_size, st.st_mtime_ns)
                    counts["unchanged"] += 1
                    continue
                known_sha = k[3] if k and not full and k[4] in DONE else None
                fut = pool.schedule(worker.process, args=(str(path), known_sha), timeout=timeout + st.st_size // (512 * 1024))
                pending[fut] = (path, st)
                if len(pending) >= workers * 4:
                    _drain(pending, con, run_id, root, counts, FIRST_COMPLETED)
            _drain(pending, con, run_id, root, counts, None)
        counts["missing"] = db.mark_missing(con, run_id, prefix)
        status = "completed"
    except KeyboardInterrupt:
        status = "aborted"
        raise
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        db.finish_run(con, run_id, status, dict(counts))
        con.close()
    return counts


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


def _drain(pending: dict, con, run_id: int, root: Path, counts: Counter, until) -> None:
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
        db.write_result(con, run_id, str(path), area, st.st_size, st.st_mtime_ns, result)
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
