import os
import sqlite3

import pytest

from conftest import KEY
from piiscan import db, scan
from piiscan.detect import value_hmac
from piiscan.synth import corpus, docs
from piiscan.synth.values import ssn


@pytest.fixture
def share(tmp_path, rng):
    root = tmp_path / "share"
    return root, corpus.build(root, rng)


def run(root, db):
    return scan.run(root, db, KEY, workers=2, timeout=60)


def q(db, sql, *args):
    con = sqlite3.connect(db)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def test_full_scan_finds_every_planted_value(share, tmp_path):
    root, truth = share
    db = tmp_path / "piiscan.db"
    run(root, db)
    rows = q(db, "SELECT path, pii_type, value_hmac FROM current_findings")
    got = {(os.path.relpath(p.split("!/")[0], root), t, h) for p, t, h in rows}
    for rel, types in truth.items():
        for pii_type, values in types.items():
            for v in values:
                assert (str(rel).replace("/", os.sep), pii_type, value_hmac(KEY, pii_type, v)) in got, (rel, pii_type)

    expected_dls = {(rel.replace("/", os.sep), value_hmac(KEY, "DRIVERS_LICENSE", v))
                    for rel, types in truth.items() for v in types["DRIVERS_LICENSE"]}
    assert {(r, h) for r, t, h in got if t == "DRIVERS_LICENSE"} == expected_dls

    status = dict(q(db, "SELECT path, last_status FROM files WHERE parent_file_id IS NULL"))
    by_name = {os.path.basename(p): s for p, s in status.items()}
    assert by_name["locked.pdf"] == by_name["locked.docx"] == "encrypted"
    assert by_name["broken.pdf"] == "corrupt"
    assert by_name["tool.bin"] == "unsupported"
    assert by_name["scan.pdf"] == by_name["fax.tif"] == "ok"

    rotated = {os.path.basename(p): r for p, r in q(
        db, "SELECT f.path, s.rotated_pages FROM file_scans s JOIN files f"
            " ON f.file_id = s.file_id AND s.run_id = f.last_scanned_run WHERE f.parent_file_id IS NULL")}
    assert (rotated["scan.pdf"], rotated["sideways.pdf"], rotated["fax.tif"], rotated["w9_form.pdf"]) == (1, 1, 1, 0)
    assert q(db, "SELECT status FROM scan_runs") == [("completed",)]
    assert {a for (a,) in q(db, "SELECT area FROM files")} >= {"Billing", "HR", "Mail", "Archive", "Scans"}


def test_incremental_rescan(share, tmp_path, rng):
    root, _ = share
    db = tmp_path / "piiscan.db"
    run(root, db)
    current = "SELECT pii_type, value_hmac, path FROM current_findings ORDER BY 1, 2, 3"
    first = q(db, current)

    counts = run(root, db)
    assert counts["unchanged"] > 0 and q(db, current) == first
    assert counts["ok"] == 0

    s = ssn(rng)
    (root / "Billing" / "notes.txt").write_bytes(docs.text([f"new SSN {s}"]))
    os.utime(root / "Billing" / "notes.txt", ns=(1, 1))
    (root / "Archive" / "memo.rtf").unlink()
    (root / "Archive" / "batch.zip").write_bytes(docs.zip_({"only.txt": b"nothing here"}))
    run(root, db)

    current = q(db, "SELECT path, value_hmac FROM current_findings")
    assert any(p.endswith("notes.txt") and h == value_hmac(KEY, "SSN", s.replace("-", "")) for p, h in current)
    assert not any(p.endswith("memo.rtf") for p, _ in current)
    missing = {os.path.basename(p) for (p,) in q(db, "SELECT path FROM files WHERE missing_since IS NOT NULL")}
    assert "memo.rtf" in missing and "a.txt" in missing
    assert not any("batch.zip!/" in p for p, _ in current)


def test_existing_database_is_upgraded_in_place(tmp_path):
    old = tmp_path / "old.db"
    con = sqlite3.connect(old)
    con.execute("CREATE TABLE file_scans(run_id INTEGER, file_id INTEGER, status TEXT NOT NULL, error_where TEXT,"
                " pages INTEGER, ocr_pending INTEGER, duration_ms INTEGER, scanned_at TEXT NOT NULL,"
                " PRIMARY KEY(run_id, file_id))")
    con.execute("INSERT INTO file_scans VALUES (1, 1, 'ok', NULL, 1, 0, 5, 'then')")
    con.commit()
    con.close()
    db.connect(old).close()
    assert q(old, "SELECT status, rotated_pages FROM file_scans") == [("ok", None)]


def test_refuses_concurrent_run(share, tmp_path):
    root, _ = share
    db = tmp_path / "piiscan.db"
    run(root, db)
    con = sqlite3.connect(db)
    con.execute("UPDATE scan_runs SET status = 'running'")
    con.commit()
    con.close()
    with pytest.raises(SystemExit):
        run(root, db)
    scan.run(root, db, KEY, workers=2, timeout=60, force=True)
    assert ("aborted",) in q(db, "SELECT status FROM scan_runs")
