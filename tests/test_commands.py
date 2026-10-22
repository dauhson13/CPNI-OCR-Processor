import json
import plistlib
import sqlite3

import pytest

from conftest import KEY
from piiscan import db, ocr, scan, schedule
from piiscan.review import review
from piiscan.synth import docs


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
