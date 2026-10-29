import json
import random
import threading
import time
from types import SimpleNamespace as Event

import pytest

from piiscan import labeling, ocr
from piiscan.rules import Rules
from piiscan.synth import docs

DL = "Identification: Driver's license #"
PHONE = {"type": "PHONE_NUMBER", "box": [0.1, 0.1, 0.4, 0.15], "text": "(800) 555-0100", "value": "8005550100",
         "source": "ocr_print", "confidence": 0.9}
SSN = {"type": "SSN", "box": [0.1, 0.3, 0.4, 0.35], "text": "123-45-6789", "value": "123456789", "source": "ocr_print",
       "confidence": 0.9}


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


def fake_suggestions(straight, page, rules=None):
    return [dict(f) for f in (PHONE, SSN) if not (rules and rules.skips(f["type"], f["value"]))]


def tk_root():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    return root


@pytest.fixture
def window(scans, tmp_path, monkeypatch):
    root = tk_root()
    monkeypatch.setattr(labeling, "suggestions", fake_suggestions)
    win = labeling.LabelWindow(root, scans, labeling.Store(tmp_path / "training", Rules(tmp_path / "rules.json")))
    win.detect = lambda image: 0.0
    win.confirm = lambda *a, **k: True
    win.wait_idle()
    yield win
    win.requests.put(None)
    root.destroy()


def opened(win, index=0):
    win.open_file(index)
    win.wait_idle()
    win.tk.update()
    win.render()
    return win


def center(win, box):
    x0, y0, x1, y1 = box
    return Event(x=(x0 + x1) / 2 * win.straight.width * win.scale, y=(y0 + y1) / 2 * win.straight.height * win.scale)


def draw(win, a, b):
    win.press(Event(x=a[0], y=a[1]))
    win.drag(Event(x=b[0], y=b[1]))
    win.release(Event(x=b[0], y=b[1]))


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
    rules = Rules()
    names = rules.names()
    assert {name.split(":")[0] for name in names} == {"Identification", "SSN", "Bank info", "CPNI", "Other", labeling.NONE}
    assert list(names)[-1] == labeling.NONE
    for wanted in (DL, "CPNI: Customer account #", "CPNI: Phone #", "CPNI: Call detail", "CPNI: IP address",
                   "CPNI: MAC address", "CPNI: Equipment serial / device ID", "CPNI: Circuit ID",
                   "CPNI: Usage (minutes / data)", "CPNI: Payment history", "CPNI: Service / E911 address",
                   "CPNI: Account password / PIN", "CPNI: Services / plan / features", "CPNI: Billing amount"):
        assert wanted in names
    codes = list(names.values())
    assert len({rules.color(c) for c in codes}) == len(codes)


def test_custom_types_save_update_and_persist(scans, tmp_path):
    path = tmp_path / "rules.json"
    rules = Rules(path)
    rec = rules.add_type("CPNI", "Port-out PIN", "port out pin, transfer pin")
    store = labeling.Store(tmp_path / "training", rules)
    page = labeling.load_page(scans / "form.pdf", 1)
    saved = store.save(scans / "form.pdf", 1, page, (0, 0, 60, 30), ["CPNI: Port-out PIN"], "4821", True, 0.0, 0.0)
    assert saved["types"] == [rec["code"]] == ["PORT_OUT_PIN"]
    assert store.update(saved["id"], ["SSN", "CPNI: Port-out PIN"], "4821", True)["types"] == ["SSN", "PORT_OUT_PIN"]
    with pytest.raises(ValueError):
        store.save(scans / "form.pdf", 1, page, (0, 0, 60, 30), ["CPNI: Not a type"], "4821", True, 0.0, 0.0)
    reloaded = Rules(path)
    order = list(reloaded.names())
    assert reloaded.names()["CPNI: Port-out PIN"] == "PORT_OUT_PIN"
    assert order.index("CPNI: Port-out PIN") < order.index("Other: Name")
    assert reloaded.color("PORT_OUT_PIN") not in {reloaded.color(c) for c in Rules().codes()}


def test_window_reads_pages_in_the_background(window):
    win = window
    assert [f.name for f in win.files] == ["form.pdf", "id_form.pdf", "fax.tif"]
    assert win.progress_label.cget("text") == "0 of 3 complete"
    assert any("undo" in what for _, what in win.shortcuts())
    win.open_file(0)
    assert win.busy and win.straight is None
    win.press(Event(x=10, y=150))
    assert win.drag_start is None and "Still reading" in win.status.cget("text")
    win.wait_idle()
    assert not win.busy and win.straight is not None
    assert [f["type"] for f in win.visible()] == ["PHONE_NUMBER", "SSN"]
    assert win.rotations == {1: (0.0, 0.0)} and "2 found by the scanner" in win.status.cget("text")


def test_stale_results_are_dropped(window, monkeypatch):
    win = window
    gate, calls = threading.Event(), []

    def slow(straight, page, rules=None):
        calls.append(page)
        n = len(calls)
        if n == 1:
            gate.wait(10)
        return [dict(SSN, text=f"read {n}")]

    monkeypatch.setattr(labeling, "suggestions", slow)
    win.open_file(0)
    deadline = time.monotonic() + 30
    while not calls and time.monotonic() < deadline:
        time.sleep(0.01)
    win.open_file(1)
    gate.set()
    win.wait_idle()
    assert win.file.name == "id_form.pdf" and [f["text"] for f in win.found] == ["read 2"]


def test_bypass_hides_a_suggestion_everywhere(window, tmp_path):
    win = opened(window)
    phone = next(f for f in win.visible() if f["type"] == "PHONE_NUMBER")
    win.press(center(win, phone["box"]))
    assert win.selected is phone and win.text_var.get() == "(800) 555-0100"
    win.bypass()
    assert [f["type"] for f in win.visible()] == ["SSN"] and "Bypassed everywhere" in win.status.cget("text")
    saved = json.loads((tmp_path / "rules.json").read_text())["bypass"]
    assert saved[0]["types"] == ["PHONE_NUMBER"] and saved[0]["value"] == "(800) 555-0100"
    opened(win, 1)
    assert [f["type"] for f in win.visible()] == ["SSN"]
    win.bypass()
    assert len(win.store.rules.bypass) == 1 and "Bypassed" not in win.status.cget("text")


def test_custom_type_undo_and_removal(window):
    win = opened(window)
    rec = win.add_type("Other", "Employee ID", "employee id, emp #")
    name = "Other: Employee ID"
    assert win.type_vars[name].get() and rec["code"] in win.status.cget("text")
    draw(win, (20, 120), (100, 140))
    win.text_var.set("E-4471")
    win.save()
    assert [r["types"] for r in win.store.labels()] == [["EMPLOYEE_ID"]]
    assert win.listbox.get(0).endswith("[1]")
    assert "use this type" in win.remove_type("EMPLOYEE_ID") and name in win.store.rules.names()
    label_id = win.store.labels()[0]["id"]
    win.undo()
    assert win.store.labels() == [] and not (win.store.root / "crops" / f"{label_id}.png").exists()
    assert "Undid your last label" in win.status.cget("text") and not win.listbox.get(0).endswith("]")
    win.undo()
    assert win.status.cget("text") == "Nothing to undo."
    assert win.remove_type("EMPLOYEE_ID") == "Type removed." and name not in win.type_vars


def test_filter_search_and_progress(window, scans):
    win = window
    win.search_var.set("FAX")
    assert win.shown == [scans / "sub" / "fax.tif"] and win.listbox.size() == 1
    assert win.progress_label.cget("text") == "0 of 3 complete, showing 1"
    win.search_var.set("")
    opened(win)
    win.filter_var.set("Not complete")
    win.complete()
    win.wait_idle()
    assert win.file.name == "id_form.pdf" and [p.name for p in win.shown] == ["id_form.pdf", "fax.tif"]
    assert win.progress_label.cget("text") == "1 of 3 complete, showing 2"
    assert win.status.cget("text").startswith("Marked complete: 1 of 3 done.")
    assert win.listbox.curselection() == (0,)


def test_zoomed_boxes_land_on_the_right_pixels(window):
    win = opened(window)
    fit = win.scale
    win.zoom_by(2.0)
    assert win.scale == pytest.approx(2 * fit) and win.zoom_label.cget("text") == "Zoom: 200%"
    win.canvas.xview_moveto(0.5)
    win.canvas.yview_moveto(0.5)
    ox, oy = win.canvas.canvasx(0), win.canvas.canvasy(0)
    assert ox > 0 and oy > 0
    draw(win, (10, 10), (60, 30))
    s = win.scale
    assert win.box == (int((ox + 10) / s), int((oy + 10) / s), int((ox + 60) / s), int((oy + 30) / s))
    win.clear_box()
    win.zoom_by(None)
    assert win.scale == pytest.approx(fit) and win.zoom_label.cget("text") == "Zoom: fit"


def test_unsaved_box_asks_before_leaving(window):
    win = opened(window)
    draw(win, (20, 120), (100, 140))
    win.type_vars["SSN"].set(True)
    win.text_var.set("123-45-6789")
    asked = []
    win.confirm = lambda title, *a, **k: asked.append(title) or False
    win.next_document()
    win.complete()
    win.go_page(1)
    assert asked == ["Unsaved label"] * 2 and win.file.name == "form.pdf" and win.store.completed() == set()
    win.confirm = lambda *a, **k: True
    win.next_document()
    win.wait_idle()
    assert win.file.name == "id_form.pdf"
    win.confirm = lambda *a, **k: pytest.fail("asked although nothing was changed")
    win.press(center(win, win.visible()[0]["box"]))
    win.next_document()
    win.wait_idle()
    assert win.file.name == "fax.tif"


def test_delete_key_only_outside_the_text_box(window):
    win = opened(window)
    draw(win, (20, 120), (100, 140))
    win.type_vars["SSN"].set(True)
    win.text_var.set("123-45-6789")
    win.save()
    rec = win.store.labels()[0]
    win.press(center(win, rec["box"]))
    assert win.editing["id"] == rec["id"]
    win._key_delete(Event(widget=win.entry))
    assert len(win.store.labels()) == 1
    win._key_delete(Event(widget=win.canvas))
    assert win.store.labels() == []


def test_errors_show_only_their_type(window, monkeypatch):
    win = window

    def boom():
        raise ValueError("Customer SSN 123-45-6789")

    win.tk.after(0, boom)
    for _ in range(50):
        win.tk.update()
        if "Something went wrong" in win.status.cget("text"):
            break
    text = win.status.cget("text")
    assert "ValueError at test_labeling.py" in text and "123-45-6789" not in text

    def broken(straight, page, rules=None):
        raise RuntimeError("Customer SSN 123-45-6789")

    monkeypatch.setattr(labeling, "suggestions", broken)
    opened(win)
    text = win.status.cget("text")
    assert "Couldn't read this page (RuntimeError" in text and "123-45-6789" not in text and not win.busy


@pytest.mark.skipif(not ocr.models_ready(), reason="run `uv run scripts/setup.py` to install OCR models")
def test_window_end_to_end(scans, tmp_path):
    root = tk_root()
    try:
        store = labeling.Store(tmp_path / "training", Rules(tmp_path / "rules.json"))
        win = labeling.LabelWindow(root, scans, store)
        win.confirm = lambda *a, **k: True
        win.wait_idle()
        assert [f.name for f in win.files] == ["form.pdf", "id_form.pdf", "fax.tif"]

        opened(win)
        assert abs(win.detected + 3) <= 1
        draw(win, (50, 100), (300, 140))
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
        win.wait_idle()
        assert win.final == round(win.detected + 90, 1)
        viewed = [win.detected, win.final]
        win.complete()
        win.wait_idle()
        assert store.completed() == {str(scans / "form.pdf")} and win.file.name == "id_form.pdf"
        done = [json.loads(line) for line in store.done_path.read_text().splitlines()]
        assert done[0]["rotations"] == {"1": viewed} and done[0]["pages"] == 1

        found = {f["type"]: f for f in win.visible()}
        assert {"SSN", "DRIVERS_LICENSE"} <= set(found)
        assert found["SSN"]["text"] == "123-45-6789" and found["DRIVERS_LICENSE"]["text"] == "A1234567"
        target = center(win, found["DRIVERS_LICENSE"]["box"])
        win.press(target)
        assert win.selected is found["DRIVERS_LICENSE"] and win.text_var.get() == "A1234567"
        assert [n for n, v in win.type_vars.items() if v.get()] == [DL]
        win.render()
        assert win.selected is found["DRIVERS_LICENSE"] and win.box is not None
        win.type_vars[labeling.NONE].set(True)
        win.ticked(labeling.NONE)
        win.save()
        corrected = store.labels()[-1]
        assert corrected["types"] == ["NONE"] and corrected["suggested"] == "DRIVERS_LICENSE"
        assert "DRIVERS_LICENSE" not in {f["type"] for f in win.visible()}

        win.press(target)
        assert win.editing["id"] == corrected["id"]
        win.type_vars["SSN"].set(True)
        win.ticked("SSN")
        win.save()
        assert [r["types"] for r in store.labels() if r["id"] == corrected["id"]] == [["SSN"]]
        win.press(target)
        win.delete()
        assert corrected["id"] not in {r["id"] for r in store.labels()}
        assert "DRIVERS_LICENSE" in {f["type"] for f in win.visible()}

        win.next_document()
        win.wait_idle()
        assert win.file.name == "fax.tif"
        win.next_document()
        assert win.file.name == "fax.tif" and "last document" in win.status.cget("text")
        win.requests.put(None)
    finally:
        root.destroy()
