import json
import random
from types import SimpleNamespace as Event

import pytest

from piiscan import labeling, ocr
from piiscan.synth import docs


@pytest.fixture
def scans(tmp_path):
    rng = random.Random(4)
    folder = tmp_path / "scans"
    (folder / "sub").mkdir(parents=True)
    (folder / "form.pdf").write_bytes(docs.pdf_scanned(docs.filler_lines(rng), rotate=3))
    (folder / "id_form.pdf").write_bytes(docs.pdf_scanned(
        docs.filler_lines(rng, 6) + ["Customer SSN: 123-45-6789", "Driver's License: A1234567"] + docs.filler_lines(rng, 6)))
    (folder / "sub" / "fax.tif").write_bytes(docs.tiff(images=[docs.page_image(docs.filler_lines(rng))] * 2))
    (folder / "notes.txt").write_text("not a scan")
    return folder


def test_finds_scans_and_pages(scans):
    files = list(labeling.scan_files(scans))
    assert [f.name for f in files] == ["form.pdf", "id_form.pdf", "fax.tif"]
    assert [labeling.page_count(f) for f in files] == [1, 1, 2]
    assert labeling.load_page(files[2], 2).mode == "RGB"


def test_store_saves_crop_and_record(scans, tmp_path):
    store = labeling.Store(tmp_path / "training")
    page = labeling.load_page(scans / "form.pdf", 1)
    rec = store.save(scans / "form.pdf", 1, page, (100, 200, 400, 260), ["SSN", "CPNI: Customer account #"],
                     "123-45-6789", True, 3.0, 3.0, suggested="DRIVERS_LICENSE")
    assert rec["types"] == ["SSN", "CUSTOMER_ACCOUNT"] and rec["suggested"] == "DRIVERS_LICENSE"
    assert rec["handwritten"] and rec["box"][0] == round(100 / page.width, 5)
    from PIL import Image

    assert Image.open(tmp_path / "training" / "crops" / f"{rec['id']}.png").size == (300, 60)
    assert [json.loads(line)["id"] for line in (tmp_path / "training" / "labels.jsonl").read_text().splitlines()] == [rec["id"]]
    for bad in [dict(labels=[]), dict(labels=["Nope"]), dict(labels=[labeling.NONE, "SSN"]), dict(text="  "),
                dict(box=(0, 0, 2, 2))]:
        args = dict(labels=["SSN"], text="1", box=(0, 0, 50, 50)) | bad
        with pytest.raises(ValueError):
            store.save(scans / "form.pdf", 1, page, args["box"], args["labels"], args["text"], False, 0.0, 0.0)
    assert store.save(scans / "form.pdf", 1, page, (0, 0, 50, 50), [labeling.NONE], "hello", True, 0.0, 0.0)["types"] == ["NONE"]
    assert labeling.label_types({"type": "SSN"}) == ["SSN"]


def test_every_requested_category_is_offered_in_its_own_color():
    groups = {name.split(":")[0] for name in labeling.LABEL_TYPES}
    assert groups == {"Identification", "SSN", "Bank info", "CPNI", "Other", labeling.NONE}
    codes = list(labeling.LABEL_TYPES.values())
    assert set(codes) <= set(labeling.COLORS)
    assert len({labeling.COLORS[c] for c in codes}) == len(codes)


@pytest.mark.skipif(not ocr.models_ready(), reason="run `uv run scripts/setup.py` to install OCR models")
def test_window_end_to_end(scans, tmp_path):
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    try:
        store = labeling.Store(tmp_path / "training")
        win = labeling.LabelWindow(root, scans, store)
        while win.walking:
            root.update()
        assert [f.name for f in win.files] == ["form.pdf", "id_form.pdf", "fax.tif"]

        win.open_file(0)
        assert abs(win.detected + 3) <= 1
        win.press(Event(x=50, y=100))
        win.drag(Event(x=300, y=140))
        win.release(Event(x=300, y=140))
        for name in ("CPNI: Customer account #", labeling.NONE):
            win.type_vars[name].set(True)
            win.ticked(name)
        assert [n for n, v in win.type_vars.items() if v.get()] == [labeling.NONE]
        for name in ("CPNI: Customer account #", "SSN"):
            win.type_vars[name].set(True)
            win.ticked(name)
        win.text_var.set("01234567890")
        win.save()
        saved = store.labels()
        assert len(saved) == 1 and saved[0]["types"] == ["SSN", "CUSTOMER_ACCOUNT"] and saved[0]["suggested"] is None
        win.turn(90)
        assert win.final == round(win.detected + 90, 1)
        viewed = [win.detected, win.final]
        win.complete()
        assert store.completed() == {str(scans / "form.pdf")} and win.file.name == "id_form.pdf"
        done = [json.loads(line) for line in store.done_path.read_text().splitlines()]
        assert done[0]["rotations"] == {"1": viewed} and done[0]["pages"] == 1

        found = {f["type"]: f for f in win.visible()}
        assert {"SSN", "DRIVERS_LICENSE"} <= set(found)
        assert found["SSN"]["text"] == "123-45-6789" and found["DRIVERS_LICENSE"]["text"] == "A1234567"
        x0, y0, x1, y1 = found["DRIVERS_LICENSE"]["box"]
        center = Event(x=(x0 + x1) / 2 * win.straight.width * win.scale, y=(y0 + y1) / 2 * win.straight.height * win.scale)
        win.press(center)
        assert win.selected is found["DRIVERS_LICENSE"] and win.text_var.get() == "A1234567"
        assert [n for n, v in win.type_vars.items() if v.get()] == ["Identification: Driver's license"]
        win.render()
        assert win.selected is found["DRIVERS_LICENSE"] and win.box is not None
        win.type_vars[labeling.NONE].set(True)
        win.ticked(labeling.NONE)
        win.save()
        corrected = store.labels()[-1]
        assert corrected["types"] == ["NONE"] and corrected["suggested"] == "DRIVERS_LICENSE"
        assert "DRIVERS_LICENSE" not in {f["type"] for f in win.visible()}

        win.press(center)
        assert win.editing["id"] == corrected["id"]
        win.type_vars["SSN"].set(True)
        win.ticked("SSN")
        win.save()
        assert [r["types"] for r in store.labels() if r["id"] == corrected["id"]] == [["SSN"]]
        win.press(center)
        win.delete()
        assert corrected["id"] not in {r["id"] for r in store.labels()}
        assert "DRIVERS_LICENSE" in {f["type"] for f in win.visible()}

        win.next_document()
        assert win.file.name == "fax.tif"
        win.next_document()
        assert win.file.name == "fax.tif" and "last document" in win.status.cget("text")
    finally:
        root.destroy()
