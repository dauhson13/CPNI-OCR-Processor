import getpass
import json
import platform
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB = PROJECT_DIR / "data" / "piiscan.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs(
    run_id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, host TEXT, os_user TEXT,
    root TEXT NOT NULL, config_sha256 TEXT, tool_version TEXT, status TEXT NOT NULL, counts TEXT);
CREATE TABLE IF NOT EXISTS files(
    file_id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, parent_file_id INTEGER REFERENCES files,
    member_path TEXT, area TEXT, ext TEXT, detected_type TEXT, size INTEGER, mtime_ns INTEGER, sha256 TEXT,
    owner TEXT, first_seen_run INTEGER, last_seen_run INTEGER, last_scanned_run INTEGER, last_status TEXT,
    missing_since INTEGER);
CREATE TABLE IF NOT EXISTS file_scans(
    run_id INTEGER NOT NULL REFERENCES scan_runs, file_id INTEGER NOT NULL REFERENCES files,
    status TEXT NOT NULL, error_where TEXT, pages INTEGER, ocr_pages INTEGER, duration_ms INTEGER,
    scanned_at TEXT NOT NULL, rotated_pages INTEGER, PRIMARY KEY(run_id, file_id));
CREATE TABLE IF NOT EXISTS findings(
    finding_id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES scan_runs,
    file_id INTEGER NOT NULL REFERENCES files, page INTEGER, locator TEXT, x0 REAL, y0 REAL, x1 REAL, y1 REAL,
    pii_type TEXT NOT NULL, value_hmac TEXT NOT NULL, confidence REAL NOT NULL, method TEXT NOT NULL,
    review_status TEXT NOT NULL, reviewed_by TEXT, reviewed_at TEXT);
CREATE INDEX IF NOT EXISTS findings_by_file ON findings(file_id, run_id);
CREATE INDEX IF NOT EXISTS findings_by_hmac ON findings(value_hmac);
CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, run_id INTEGER, detail TEXT);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE VIEW IF NOT EXISTS current_findings AS
    SELECT fi.*, f.path, f.area FROM findings fi JOIN files f ON f.file_id = fi.file_id
    WHERE fi.run_id = f.last_scanned_run AND f.missing_since IS NULL;
"""

REVIEW_THRESHOLD = 0.6


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript(SCHEMA)
    cols = {row[1] for row in con.execute("PRAGMA table_info(file_scans)")}
    if "rotated_pages" not in cols:
        con.execute("ALTER TABLE file_scans ADD COLUMN rotated_pages INTEGER")
    if "ocr_pending" in cols:
        con.execute("ALTER TABLE file_scans RENAME COLUMN ocr_pending TO ocr_pages")
    if "scanner" not in {row[1] for row in con.execute("PRAGMA table_info(files)")}:
        con.execute("ALTER TABLE files ADD COLUMN scanner TEXT")
    return con


def audit(con, action: str, run_id: int | None = None, detail: dict | None = None) -> None:
    with con:
        con.execute("INSERT INTO audit_log(ts, actor, action, run_id, detail) VALUES (?,?,?,?,?)",
                    (now(), getpass.getuser(), action, run_id, json.dumps(detail) if detail else None))


def start_run(con, root: str, config: dict, config_sha256: str, version: str, force: bool) -> int:
    running = con.execute("SELECT run_id FROM scan_runs WHERE status = 'running'").fetchall()
    if running and not force:
        raise SystemExit("piiscan: another scan is running against this DB (or one crashed); rerun with --force")
    with con:
        for (rid,) in running:
            con.execute("UPDATE scan_runs SET status = 'aborted', finished_at = ? WHERE run_id = ?", (now(), rid))
        run_id = con.execute(
            "INSERT INTO scan_runs(started_at, host, os_user, root, config_sha256, tool_version, status)"
            " VALUES (?,?,?,?,?,?, 'running')",
            (now(), platform.node(), getpass.getuser(), root, config_sha256, version)).lastrowid
    audit(con, "scan_start", run_id, config)
    return run_id


def finish_run(con, run_id: int, status: str, counts: dict) -> None:
    with con:
        con.execute("UPDATE scan_runs SET status = ?, finished_at = ?, counts = ? WHERE run_id = ?",
                    (status, now(), json.dumps(counts), run_id))
    audit(con, f"scan_{status}", run_id, counts)


def known_files(con, root: str) -> dict:
    rows = con.execute(
        "SELECT path, file_id, size, mtime_ns, sha256, last_status, scanner FROM files"
        " WHERE parent_file_id IS NULL AND substr(path, 1, length(?)) = ?", (root, root))
    return {r[0]: r[1:] for r in rows}


def record_unchanged(con, run_id: int, file_id: int, path: str, size: int, mtime_ns: int) -> None:
    with con:
        con.execute("UPDATE files SET size = ?, mtime_ns = ?, last_seen_run = ?, missing_since = NULL WHERE file_id = ?",
                    (size, mtime_ns, run_id, file_id))
        prefix = path + "!/"
        con.execute("UPDATE files SET last_seen_run = ?, missing_since = NULL WHERE substr(path, 1, length(?)) = ?",
                    (run_id, prefix, prefix))
        con.execute("INSERT OR REPLACE INTO file_scans(run_id, file_id, status, scanned_at) VALUES (?,?, 'unchanged', ?)",
                    (run_id, file_id, now()))


def write_result(con, run_id: int, path: str, area: str, size: int, mtime_ns: int, result: dict,
                 scanner: str | None = None) -> None:
    ids: dict[str | None, int] = {}
    with con:
        for rec in result["records"]:
            member = rec["member"]
            full = path if member is None else f"{path}!/{member}"
            parent = None if member is None else ids.get(member.rpartition("!/")[0] or None)
            unchanged = rec["status"] == "unchanged"
            file_id = con.execute(
                """INSERT INTO files(path, parent_file_id, member_path, area, ext, detected_type, size, mtime_ns,
                       sha256, owner, first_seen_run, last_seen_run, last_scanned_run, last_status, scanner)
                   VALUES (:path, :parent, :member, :area, :ext, :type, :size, :mtime, :sha, :owner, :run, :run,
                       :scanned, :status, :scanner)
                   ON CONFLICT(path) DO UPDATE SET parent_file_id = :parent, detected_type = COALESCE(:type, detected_type),
                       size = :size, mtime_ns = :mtime, sha256 = :sha, owner = COALESCE(:owner, owner),
                       scanner = COALESCE(:scanner, scanner),
                       last_seen_run = :run, last_scanned_run = COALESCE(:scanned, last_scanned_run),
                       last_status = CASE WHEN :status = 'unchanged' THEN last_status ELSE :status END,
                       missing_since = NULL
                   RETURNING file_id""",
                {"path": full, "parent": parent, "member": member, "area": area,
                 "ext": Path(member or path).suffix.lower(), "type": rec["type"],
                 "size": size if member is None else None, "mtime": mtime_ns if member is None else None,
                 "sha": result["sha256"] if member is None else None, "owner": result["owner"] if member is None else None,
                 "run": run_id, "scanned": None if unchanged else run_id, "status": rec["status"],
                 "scanner": scanner if member is None else None}).fetchone()[0]
            ids[member] = file_id
            con.execute(
                "INSERT OR REPLACE INTO file_scans(run_id, file_id, status, error_where, pages, ocr_pages, rotated_pages,"
                " duration_ms, scanned_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (run_id, file_id, rec["status"], rec["error"], rec["pages"], rec["ocr_pages"], rec["rotated_pages"],
                 result["duration_ms"] if member is None else None, now()))
            con.executemany(
                "INSERT INTO findings(run_id, file_id, page, locator, x0, y0, x1, y1, pii_type, value_hmac,"
                " confidence, method, review_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(run_id, file_id, f["page"], f["locator"], *(f["bbox"] or (None,) * 4), f["pii_type"],
                  f["value_hmac"], f["confidence"], f["method"],
                  "auto" if f["confidence"] >= REVIEW_THRESHOLD else "needs_review") for f in rec["findings"]])
        if result["records"] and result["records"][0]["status"] == "unchanged":
            prefix = path + "!/"
            con.execute("UPDATE files SET last_seen_run = ?, missing_since = NULL WHERE substr(path, 1, length(?)) = ?",
                        (run_id, prefix, prefix))


def apply_bypass(con, hmacs: set[str]) -> dict[str, int]:
    with con:
        con.execute("CREATE TEMP TABLE IF NOT EXISTS bypass_now(h TEXT PRIMARY KEY)")
        con.execute("DELETE FROM bypass_now")
        con.executemany("INSERT OR IGNORE INTO bypass_now VALUES (?)", [(h,) for h in hmacs])
        bypassed = con.execute(
            "UPDATE findings SET review_status = 'bypassed' WHERE review_status IN ('auto', 'needs_review')"
            " AND value_hmac IN (SELECT h FROM bypass_now)").rowcount
        restored = con.execute(
            "UPDATE findings SET review_status = CASE WHEN confidence >= ? THEN 'auto' ELSE 'needs_review' END"
            " WHERE review_status = 'bypassed' AND value_hmac NOT IN (SELECT h FROM bypass_now)",
            (REVIEW_THRESHOLD,)).rowcount
    if bypassed or restored:
        audit(con, "bypass_applied", detail={"bypassed": bypassed, "restored": restored, "entries": len(hmacs)})
    return {"bypassed": bypassed, "restored": restored}


def summary(con, root: str) -> dict[str, dict]:
    def counts(sql):
        return dict(con.execute(sql, (root, root)).fetchall())

    def current(status):
        return con.execute(
            "SELECT count(*) FROM findings fi JOIN files f ON f.file_id = fi.file_id WHERE fi.run_id = f.last_scanned_run"
            " AND f.missing_since IS NULL AND fi.review_status = ? AND substr(f.path, 1, length(?)) = ?",
            (status, root, root)).fetchone()[0]

    under = "missing_since IS NULL AND substr(path, 1, length(?)) = ?"
    scanned, rotated = con.execute(
        "SELECT coalesce(sum(s.ocr_pages), 0), coalesce(sum(s.rotated_pages), 0) FROM file_scans s"
        " JOIN files f ON f.file_id = s.file_id AND s.run_id = f.last_scanned_run"
        " WHERE f.missing_since IS NULL AND substr(f.path, 1, length(?)) = ?", (root, root)).fetchone()
    return {
        "status": counts(f"SELECT last_status, count(*) FROM files WHERE {under} GROUP BY 1"),
        "type": counts(f"SELECT detected_type, count(*) FROM files WHERE {under} AND parent_file_id IS NULL GROUP BY 1"),
        "found": con.execute(
            "SELECT fi.pii_type, count(*), count(DISTINCT fi.value_hmac),"
            " count(DISTINCT CASE WHEN instr(f.path, '!/') > 0 THEN substr(f.path, 1, instr(f.path, '!/') - 1) ELSE f.path END)"
            " FROM findings fi JOIN files f ON f.file_id = fi.file_id"
            " WHERE fi.run_id = f.last_scanned_run AND f.missing_since IS NULL AND fi.review_status NOT IN ('rejected', 'bypassed')"
            " AND substr(f.path, 1, length(?)) = ? GROUP BY 1 ORDER BY 2 DESC", (root, root)).fetchall(),
        "review": current("needs_review"),
        "bypassed": current("bypassed"),
        "pages": {"scanned": scanned, "need rotation": rotated},
        "last_run": con.execute(
            "SELECT started_at, finished_at, status, counts FROM scan_runs ORDER BY run_id DESC LIMIT 1").fetchone(),
    }


def mark_missing(con, run_id: int, root: str) -> int:
    with con:
        return con.execute(
            "UPDATE files SET missing_since = ? WHERE missing_since IS NULL AND last_seen_run < ?"
            " AND substr(path, 1, length(?)) = ?", (run_id, run_id, root, root)).rowcount
