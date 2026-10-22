import argparse
import os
from pathlib import Path

from . import db, safety

ENV_FILE = db.PROJECT_DIR / ".env"


def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def main(argv=None) -> None:
    safety.install_excepthook()
    os.umask(0o077)
    load_env(ENV_FILE)
    p = argparse.ArgumentParser(prog="piiscan", description="Find where PII lives without storing it.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan the share (or a folder) and print totals")
    s.add_argument("root", type=Path, nargs="?", help="folder or share to scan (default: PIISCAN_ROOT in .env)")
    s.add_argument("--db", type=Path, default=db.DEFAULT_DB)
    s.add_argument("--key", type=Path, default=safety.DEFAULT_KEY)
    s.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    s.add_argument("--timeout", type=int, default=600, help="base seconds per file")
    s.add_argument("--full", action="store_true", help="rescan every file, ignoring what's unchanged")
    s.add_argument("--force", action="store_true", help="start even if a previous run never finished")
    t = sub.add_parser("totals", help="print the total of each kind of PII found so far")
    t.add_argument("root", type=Path, nargs="?", help="only this folder (default: PIISCAN_ROOT, or everything)")
    t.add_argument("--db", type=Path, default=db.DEFAULT_DB)
    lb = sub.add_parser("label", help="open the labeling window to mark PII on scans for training")
    lb.add_argument("root", type=Path, nargs="?", help="folder of scans (default: PIISCAN_ROOT in .env)")
    r = sub.add_parser("review", help="confirm, reject or change the type of findings (default: the low-confidence ones)")
    r.add_argument("--db", type=Path, default=db.DEFAULT_DB)
    r.add_argument("--all", action="store_true", help="go through every finding, not just low-confidence ones")
    r.add_argument("--type", dest="pii_type", help="only findings of this type, e.g. DRIVERS_LICENSE")
    tr = sub.add_parser("train", help="train the handwriting model on synthetic handwriting plus your labels")
    tr.add_argument("--steps", type=int, default=3000)
    tr.add_argument("--batch", type=int, default=16)
    ev = sub.add_parser("eval", help="measure accuracy: synthetic test set, plus your held-out labels")
    ev.add_argument("--docs", type=int, default=60, help="synthetic documents to generate and scan")
    sc = sub.add_parser("schedule", help="run the scan every night (Task Scheduler on Windows, launchd on macOS)")
    sc.add_argument("--at", default="02:00", help="time of day, HH:MM (24-hour)")
    sc.add_argument("--remove", action="store_true", help="remove the nightly scan")
    k = sub.add_parser("keygen", help="create the HMAC key used to dedupe findings")
    k.add_argument("--key", type=Path, default=safety.DEFAULT_KEY)
    args = p.parse_args(argv)
    env_root = Path(os.environ["PIISCAN_ROOT"]).expanduser() if os.environ.get("PIISCAN_ROOT") else None

    if args.cmd == "keygen":
        try:
            safety.create_key(args.key)
        except FileExistsError:
            raise SystemExit(f"piiscan: {args.key} already exists; refusing to overwrite it") from None
        print(f"created {args.key}")
    elif args.cmd == "label":
        from . import labeling

        root = args.root or env_root
        labeling.run(root if root and root.is_dir() else None)
    elif args.cmd == "totals":
        root = args.root or env_root
        print_totals(args.db, os.path.join(str(root.absolute()), "") if root else "")
    elif args.cmd == "review":
        from .review import review

        done = review(args.db, everything=args.all, pii_type=args.pii_type)
        print(f"\nconfirmed {done['confirmed']}, rejected {done['rejected']}, type changed {done['corrected']}")
    elif args.cmd == "train":
        from .train import train

        train(steps=args.steps, batch=args.batch, log=lambda line: print(line, flush=True))
    elif args.cmd == "eval":
        from .evaluate import evaluate

        evaluate(docs=args.docs)
    elif args.cmd == "schedule":
        from . import schedule

        print(schedule.remove() if args.remove else schedule.install(args.at))
    else:
        from . import scan

        root = args.root or env_root
        if root is None:
            p.error(f"give a folder to scan, or set PIISCAN_ROOT in {ENV_FILE}")
        if not root.is_dir():
            p.error("the folder to scan doesn't exist or isn't readable (is the share mounted?)")
        counts = scan.run(root, args.db, safety.load_key(args.key), args.workers, args.timeout, args.full, args.force)
        print("this run:", _fmt({k: v for k, v in counts.items() if not k.startswith("found:")}))
        print_totals(args.db, os.path.join(str(root.absolute()), ""))


def print_totals(db_path: Path, root: str) -> None:
    con = db.connect(db_path)
    try:
        totals = db.summary(con, root)
    finally:
        con.close()
    print("files by status:", _fmt(totals["status"]))
    print("files by type:  ", _fmt(totals["type"]))
    print("scanned pages:  ", _fmt(totals["pages"]))
    print()
    print(f"{'PII type':<20}{'found':>10}{'different':>12}{'files':>10}")
    for pii_type, found, distinct, files in totals["found"]:
        print(f"{pii_type:<20}{found:>10}{distinct:>12}{files:>10}")
    if not totals["found"]:
        print(f"{'(none)':<20}")
    if totals["review"]:
        print(f"\n{totals['review']} low-confidence finding(s) are waiting in `uv run main.py review`.")


def _fmt(d: dict) -> str:
    return ", ".join(f"{k} {v}" for k, v in sorted(d.items(), key=lambda kv: str(kv[0]))) or "none"
