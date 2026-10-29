import json
import plistlib
import sqlite3

import pytest

from conftest import KEY
from piiscan import cli, db, ocr, scan, schedule
from piiscan.detect import value_hmac
from piiscan.review import review
from piiscan.rules import Rules
from piiscan.synth import docs

COMPANY = value_hmac(KEY, "PHONE_NUMBER", "8005550123")


@pytest.fixture
def scanned(tmp_path):
    root = tmp_path / "share"
    root.mkdir()
    (root / "a.txt").write_bytes(docs.text(["Customer SSN 123-45-6789", "ref 234567890"]))
    (root / "b.txt").write_bytes(docs.text(["Driver's License: A1234567"]))
    dbfile = tmp_path / "piiscan.db"
    scan.run(root, dbfile, KEY, workers=1, timeout=60)
    return root, dbfile


def test_totals_and_review(scanned):
    root, dbfile = scanned
    con = db.connect(dbfile)
    found = {t: (n, d, f) for t, n, d, f in db.summary(con, "")["found"]}
    con.close()
    assert found["SSN"] == (2, 2, 1)
    answers = iter(["r"])
    assert review(dbfile, ask=lambda _: next(answers), say=lambda *_: None) == {"confirmed": 0, "rejected": 1, "corrected": 0}
    con = db.connect(dbfile)
    assert {t: n for t, n, *_ in db.summary(con, "")["found"]}["SSN"] == 1
    assert con.execute("SELECT count(*) FROM audit_log WHERE action = 'review_rejected'").fetchone()[0] == 1
    con.close()


def test_schedule_entries_without_installing():
    plist = plistlib.loads(schedule.launchd_plist(2, 30))
    assert plist["StartCalendarInterval"] == {"Hour": 2, "Minute": 30} and plist["ProgramArguments"][-2:] == [
        str(db.PROJECT_DIR / "main.py"), "scan"]
    args = schedule.schtasks_args(2, 5)
    assert args[args.index("/ST") + 1] == "02:05" and args[args.index("/TR") + 1] == f'"{schedule.WRAPPER}"'
    assert "main.py" in schedule.windows_wrapper() and ">>" in schedule.windows_wrapper()
    with pytest.raises(SystemExit):
        schedule.install("25:00")


def test_held_out_split_and_cer():
    from piiscan.train import cer, held_out

    share = sum(held_out(f"{i:032x}") for i in range(2000)) / 2000
    assert 0.07 < share < 0.13 and held_out("abc") == held_out("abc")
    assert cer("abc", "abd") == pytest.approx(1 / 3) and cer("", "") == 0


@pytest.mark.skipif(not ocr.models_ready(), reason="run `uv run scripts/setup.py` to install OCR models")
def test_eval_finds_everything_in_digital_documents():
    from piiscan.evaluate import detection_metrics

    _, by_kind = detection_metrics(5)
    assert by_kind["text"] == by_kind["docx"] == by_kind["pdf_text"] == 1.0


@pytest.mark.skipif(not ocr.models_ready(), reason="run `uv run scripts/setup.py` to install OCR models")
def test_every_planted_type_is_found_in_digital_documents():
    import io
    import random

    from faker import Faker

    from piiscan import worker
    from piiscan.evaluate import KEY as EVAL_KEY
    from piiscan.evaluate import fields, synthetic_docs

    worker.init(EVAL_KEY, quiet=False)
    planted, missed, extra = set(), [], []
    for kind, name, data, truth in synthetic_docs(60):
        if kind in ("text", "docx", "pdf_text"):
            out: list[dict] = []
            worker.scan_blob(io.BytesIO(data), name, None, 0, out)
            found = {(f["pii_type"], f["value_hmac"]) for r in out for f in r["findings"]}
            planted |= {t for t, _ in truth}
            missed += [t for t, _ in truth - found]
            extra += [t for t, _ in found - truth]
    assert missed == [] and extra == []
    assert planted == {f[2] for f in fields(random.Random(0), Faker("en_US"))}


@pytest.mark.skipif(not (ocr.MODELS_DIR / "hf" / "trocr-small-stage1" / "config.json").exists(),
                    reason="run `uv run scripts/setup.py` to install the handwriting base model")
def test_train_smoke(tmp_path):
    from piiscan.synth import handwriting as hw
    from piiscan.train import train

    store = tmp_path / "training"
    (store / "crops").mkdir(parents=True)
    image, text = next(hw.lines(1, seed=3))
    image.save(store / "crops" / "abc.png")
    (store / "labels.jsonl").write_text(json.dumps({"id": "abc", "text": text, "handwritten": True}) + "\n")
    report = train(steps=2, batch=2, eval_every=2, synthetic_val=2, store_dir=store, out=tmp_path / "hw", log=lambda *_: None)
    assert (tmp_path / "hw" / "config.json").exists() and report["your_labels_train"] + report["your_labels_held_out"] == 1


def test_old_ocr_pending_column_is_renamed(tmp_path):
    old = tmp_path / "old.db"
    con = sqlite3.connect(old)
    con.execute("CREATE TABLE file_scans(run_id INTEGER, file_id INTEGER, status TEXT NOT NULL, error_where TEXT,"
                " pages INTEGER, ocr_pending INTEGER, duration_ms INTEGER, scanned_at TEXT NOT NULL,"
                " rotated_pages INTEGER, PRIMARY KEY(run_id, file_id))")
    con.execute("INSERT INTO file_scans VALUES (1, 1, 'ocr_pending', NULL, 1, 3, 5, 'then', 1)")
    con.commit()
    con.close()
    db.connect(old).close()
    con = sqlite3.connect(old)
    assert con.execute("SELECT status, ocr_pages FROM file_scans").fetchall() == [("ocr_pending", 3)]
    con.close()


@pytest.mark.skipif(not (ocr.MODELS_DIR / "hf" / "trocr-small-stage1" / "config.json").exists(),
                    reason="run `uv run scripts/setup.py` to install the handwriting base model")
def test_continued_training_never_replaces_a_better_model(tmp_path, monkeypatch):
    from piiscan import train as train_mod

    out = tmp_path / "hw"
    train_mod.train(steps=1, batch=2, eval_every=1, synthetic_val=2, store_dir=tmp_path / "none", out=out, log=lambda *_: None)
    card = (out / "model_card.json").read_text()
    scores = iter([(0.1, None, 0.1)] + [(0.5, None, 0.5)] * 5)
    monkeypatch.setattr(train_mod, "_score", lambda *a: next(scores))
    report = train_mod.train(steps=2, batch=2, eval_every=1, synthetic_val=2, store_dir=tmp_path / "none", out=out,
                             log=lambda *_: None)
    assert report == {} and (out / "model_card.json").read_text() == card

    scores = iter([(0.1, None, 0.1), (0.105, None, 0.105), (0.3, None, 0.3)])
    monkeypatch.setattr(train_mod, "_score", lambda *a: next(scores))
    report = train_mod.train(steps=2, batch=2, eval_every=1, synthetic_val=2, store_dir=tmp_path / "none", out=out,
                             log=lambda *_: None)
    assert report["step"] == 1 and report["cer_synthetic"] == 0.105


def test_eval_reads_your_labels_and_completed_documents(tmp_path):
    from PIL import Image

    from piiscan.evaluate import your_labels
    from piiscan.labeling import NONE, Store

    store = Store(tmp_path / "training")
    page = Image.new("RGB", (400, 200), "white")
    store.save(tmp_path / "a.pdf", 1, page, (0, 0, 100, 50), ["SSN", "CPNI: Phone #"], "x", True, 2.0, 0.0)
    store.save(tmp_path / "a.pdf", 2, page, (0, 0, 100, 50), [NONE], "hello", True, 0.0, 0.0)
    store.complete(tmp_path / "a.pdf", 3, {1: (2.0, 0.0), 2: (0.0, 0.0), 3: (90.0, 90.0)})
    mine = your_labels(tmp_path / "training")
    assert mine["by_type"] == {"SSN": 1, "PHONE_NUMBER": 1, "NONE": 1} and mine["documents_complete"] == 1
    assert mine["pages"] == 3 and mine["rotation_agreement"] == pytest.approx(2 / 3)


def test_review_can_change_a_findings_type(scanned):
    root, dbfile = scanned
    answers = iter(["t", str(review_types().index("SSN") + 1)])
    done = review(dbfile, ask=lambda _: next(answers), say=lambda *_: None, pii_type="DRIVERS_LICENSE")
    assert done == {"confirmed": 0, "rejected": 0, "corrected": 1}
    con = db.connect(dbfile)
    found = {t: n for t, n, *_ in db.summary(con, "")["found"]}
    assert "DRIVERS_LICENSE" not in found and found["SSN"] == 3
    detail = con.execute("SELECT detail FROM audit_log WHERE action = 'review_corrected'").fetchone()[0]
    assert '"from": "DRIVERS_LICENSE"' in detail and '"to": "SSN"' in detail
    con.close()


def review_types():
    from piiscan.review import TYPES

    return TYPES


@pytest.fixture
def company_share(tmp_path):
    root = tmp_path / "share"
    root.mkdir()
    for name in "abcd":
        (root / f"{name}.txt").write_bytes(docs.text(["Phone: (800) 555-0123", "SSN 123-45-6789"]))
    dbfile = tmp_path / "piiscan.db"
    scan.run(root, dbfile, KEY, workers=1, timeout=60)
    con = db.connect(dbfile)
    ids = [i for (i,) in con.execute("SELECT finding_id FROM findings WHERE value_hmac = ? ORDER BY 1", (COMPANY,))]
    with con:
        con.execute("UPDATE findings SET review_status = 'rejected' WHERE finding_id = ?", (ids[0],))
        con.execute("UPDATE findings SET review_status = 'confirmed' WHERE finding_id = ?", (ids[1],))
        con.execute("UPDATE findings SET review_status = 'needs_review', confidence = 0.4 WHERE finding_id = ?", (ids[3],))
    con.close()
    return root, dbfile, ids


def statuses(dbfile, ids):
    con = db.connect(dbfile)
    try:
        return [con.execute("SELECT review_status FROM findings WHERE finding_id = ?", (i,)).fetchone()[0] for i in ids]
    finally:
        con.close()


def test_scan_uses_your_types_and_skips_the_bypass_list(tmp_path):
    root = tmp_path / "share"
    root.mkdir()
    (root / "a.txt").write_bytes(docs.text(["Employee ID: 4471", "Call us at (800) 555-0123",
                                            "Customer phone: (512) 555-0199"]))
    rules = Rules(tmp_path / "rules.json")
    rules.add_type("Other", "Employee ID")
    rules.add_bypass(["PHONE_NUMBER"], "(800) 555-0123")
    dbfile = tmp_path / "piiscan.db"
    counts = scan.run(root, dbfile, KEY, workers=1, timeout=60, rules=Rules(tmp_path / "rules.json"))
    con = db.connect(dbfile)
    rows = set(con.execute("SELECT pii_type, value_hmac FROM findings").fetchall())
    con.close()
    assert ("EMPLOYEE_ID", value_hmac(KEY, "EMPLOYEE_ID", "4471")) in rows
    assert ("PHONE_NUMBER", value_hmac(KEY, "PHONE_NUMBER", "5125550199")) in rows
    assert ("PHONE_NUMBER", COMPANY) not in rows and counts["bypassed"] == 0


def test_bypass_applies_to_past_results_and_can_be_undone(company_share, tmp_path, capsys):
    root, dbfile, ids = company_share
    rules = Rules(tmp_path / "rules.json")
    rules.add_bypass(["PHONE_NUMBER"], "(800) 555-0123")
    cli.print_totals(dbfile, "", rules.hmacs(KEY))
    out = capsys.readouterr().out
    assert out.startswith("last scan:       completed, started ") and "finished" in out.splitlines()[0]
    assert statuses(dbfile, ids) == ["rejected", "confirmed", "bypassed", "bypassed"]
    assert "2 finding(s) matched your bypass list" in out
    phone_row = next(line for line in out.splitlines() if line.startswith("PHONE_NUMBER"))
    assert phone_row.split()[1:] == ["1", "1", "1"]
    con = db.connect(dbfile)
    assert db.summary(con, "")["bypassed"] == 2 and db.summary(con, "")["review"] == 0
    assert con.execute("SELECT count(*) FROM audit_log WHERE action = 'bypass_applied'").fetchone()[0] == 1
    con.close()

    seen = []
    review(dbfile, ask=lambda _: "s", say=seen.append, everything=True)
    assert sum("PHONE_NUMBER" in s for s in seen) == 1
    seen.clear()
    review(dbfile, ask=lambda _: "s", say=seen.append, pii_type="PHONE_NUMBER")
    assert sum("PHONE_NUMBER" in s for s in seen) == 1

    rules.remove_bypass(0)
    cli.print_totals(dbfile, "", rules.hmacs(KEY))
    assert statuses(dbfile, ids) == ["rejected", "confirmed", "auto", "needs_review"]
    assert "bypass list" not in capsys.readouterr().out
    con = db.connect(dbfile)
    assert con.execute("SELECT count(*) FROM audit_log WHERE action = 'bypass_applied'").fetchone()[0] == 2
    con.close()


def test_review_offers_your_types(scanned, tmp_path):
    _, dbfile = scanned
    rules = Rules(tmp_path / "rules.json")
    rules.add_type("CPNI", "Port-out PIN")
    seen = []
    answers = iter(["t", str(rules.codes().index("PORT_OUT_PIN") + 1)])
    done = review(dbfile, ask=lambda _: next(answers), say=seen.append, pii_type="DRIVERS_LICENSE", types=rules.codes())
    assert done["corrected"] == 1 and any("PORT_OUT_PIN" in s for s in seen)
    con = db.connect(dbfile)
    assert "PORT_OUT_PIN" in {t for t, *_ in db.summary(con, "")["found"]}
    con.close()


@pytest.fixture
def cli_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(cli, "RULES_PATH", tmp_path / "rules.json")
    monkeypatch.setattr(cli.safety, "install_excepthook", lambda: None)
    monkeypatch.setattr(cli.os, "umask", lambda mask: 0)
    monkeypatch.delenv("PIISCAN_ROOT", raising=False)
    key = tmp_path / "hmac.key"
    key.write_bytes(KEY)
    return tmp_path / "rules.json", key


def test_cli_totals_and_scan_use_the_rules_file(company_share, cli_paths, tmp_path, capsys):
    root, dbfile, ids = company_share
    rules_file, key = cli_paths
    cli.main(["totals", "--db", str(dbfile), "--key", str(tmp_path / "missing.key")])
    assert "bypass list" not in capsys.readouterr().out
    Rules(rules_file).add_bypass(["PHONE_NUMBER"], "(800) 555-0123")
    with pytest.raises(SystemExit):
        cli.main(["totals", "--db", str(dbfile), "--key", str(tmp_path / "missing.key")])
    cli.main(["totals", "--db", str(dbfile), "--key", str(key)])
    assert "2 finding(s) matched your bypass list" in capsys.readouterr().out

    Rules(rules_file).remove_bypass(0)
    cli.main(["totals", "--db", str(dbfile), "--key", str(key)])
    assert statuses(dbfile, ids)[2:] == ["auto", "needs_review"]
    Rules(rules_file).add_bypass(["PHONE_NUMBER"], "(800) 555-0123")
    cli.main(["scan", str(root), "--db", str(dbfile), "--key", str(key), "--workers", "1"])
    this_run = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("this run:"))
    assert "bypassed 2" in this_run and statuses(dbfile, ids)[2:] == ["bypassed", "bypassed"]


def test_totals_says_when_nothing_was_scanned_yet(tmp_path, capsys):
    cli.print_totals(tmp_path / "empty.db", "")
    assert capsys.readouterr().out.startswith("last scan:       none yet")
