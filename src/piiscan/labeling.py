import getpass
import json
import os
import queue
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

from . import db
from .rules import GROUPS, NONE, Rules
from .rules import PATH as RULES_PATH
from .safety import describe

TRAINING_DIR = db.PROJECT_DIR / "data" / "training"
SCAN_EXTS = {".pdf", ".tif", ".tiff", ".jpg", ".jpeg", ".png", ".heic"}
RENDER_SCALE = 300 / 72
MIN_BOX = 5


def label_types(rec: dict) -> list[str]:
    return rec.get("types") or [rec["type"]]


def scan_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if Path(name).suffix.lower() in SCAN_EXTS:
                yield Path(dirpath) / name


def page_count(path: Path) -> int:
    if path.suffix.lower() == ".pdf":
        import pypdfium2 as pdfium

        pdf = pdfium.PdfDocument(path)
        try:
            return len(pdf)
        finally:
            pdf.close()
    from PIL import Image

    from .extract import image

    with Image.open(path) as im:
        return getattr(im, "n_frames", 1)


def load_page(path: Path, number: int):
    if path.suffix.lower() == ".pdf":
        import pypdfium2 as pdfium

        pdf = pdfium.PdfDocument(path)
        try:
            return pdf[number - 1].render(scale=RENDER_SCALE).to_pil().convert("RGB")
        finally:
            pdf.close()
    from PIL import Image

    with Image.open(path) as im:
        im.seek(number - 1)
        return im.convert("RGB")


def suggestions(straight, page: int, rules: Rules | None = None) -> list[dict]:
    import numpy as np

    from .detect import detect
    from .ocr.engine import WEAK_WORD, read_upright

    found = []
    for span in read_upright(np.asarray(straight), page):
        for pii_type, start, end, value, conf, method in detect(span.text, span.header, rules):
            _, box, ocr_conf = span.where(start, end)
            if box:
                found.append({"type": pii_type, "box": box, "text": span.text[start:end], "value": value,
                              "source": span.source, "ocr": ocr_conf, "labeled": not method.startswith("regex"),
                              "confidence": round(conf * (0.5 + 0.5 * ocr_conf), 3)})
    kept: list[dict] = []
    hand = lambda f: f["source"] == "ocr_hand"
    for f in sorted(found, key=lambda f: (hand(f) or f["ocr"] < WEAK_WORD, not hand(f), -f["confidence"])):
        if not any(g["type"] == f["type"] and g["source"] != f["source"] and overlap(g["box"], f["box"]) for g in kept):
            kept.append(f)
    return [f for f in kept if f["labeled"] or not any(
        g["labeled"] and g["source"] != f["source"] and overlap(g["box"], f["box"]) for g in kept)]


def overlap(a, b) -> bool:
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


class Store:

    def __init__(self, root: Path = TRAINING_DIR, rules: Rules | None = None):
        self.root = root
        self.rules = rules or Rules()
        (root / "crops").mkdir(parents=True, exist_ok=True)
        self.path = root / "labels.jsonl"
        self.done_path = root / "completed.jsonl"

    def labels(self) -> list[dict]:
        return _read_jsonl(self.path)

    def completed(self) -> set[str]:
        return {rec["source"] for rec in _read_jsonl(self.done_path)}

    def save(self, source: Path, page: int, straight, box: tuple[int, int, int, int], labels: list[str], text: str,
             handwritten: bool, rotation_detected: float, rotation_final: float, suggested: str | None = None) -> dict:
        x0, y0, x1, y1 = box
        names = self.rules.names()
        _check(labels, text, names)
        if x1 - x0 < MIN_BOX or y1 - y0 < MIN_BOX:
            raise ValueError("box is too small")
        rec = {
            "id": uuid.uuid4().hex, "source": str(source), "page": page, "types": [names[x] for x in labels],
            "text": text.strip(), "handwritten": handwritten, "suggested": suggested,
            "box": [round(x0 / straight.width, 5), round(y0 / straight.height, 5),
                    round(x1 / straight.width, 5), round(y1 / straight.height, 5)],
            "rotation_detected": rotation_detected, "rotation_final": rotation_final,
            "labeled_by": getpass.getuser(), "labeled_at": _now(),
        }
        straight.crop(box).save(self.root / "crops" / f"{rec['id']}.png")
        _append(self.path, rec)
        return rec

    def update(self, label_id: str, labels: list[str], text: str, handwritten: bool) -> dict:
        names = self.rules.names()
        _check(labels, text, names)
        recs = self.labels()
        rec = next(r for r in recs if r["id"] == label_id)
        rec.update(types=[names[x] for x in labels], text=text.strip(), handwritten=handwritten,
                   edited_by=getpass.getuser(), edited_at=_now())
        rec.pop("type", None)
        _rewrite(self.path, recs)
        return rec

    def delete(self, label_id: str) -> None:
        _rewrite(self.path, [r for r in self.labels() if r["id"] != label_id])
        (self.root / "crops" / f"{label_id}.png").unlink(missing_ok=True)

    def complete(self, source: Path, pages: int, rotations: dict[int, tuple[float, float]]) -> dict:
        rec = {"source": str(source), "pages": pages,
               "rotations": {str(p): list(r) for p, r in sorted(rotations.items())},
               "completed_by": getpass.getuser(), "completed_at": _now()}
        _append(self.done_path, rec)
        return rec


def _check(labels: list[str], text: str, names: dict[str, str]) -> None:
    if not labels:
        raise ValueError("tick at least one type (or None)")
    if any(label not in names for label in labels):
        raise ValueError("unknown label type")
    if NONE in labels and len(labels) > 1:
        raise ValueError("None can't be combined with other types")
    if not text.strip():
        raise ValueError("type exactly what the box says")


def _rewrite(path: Path, recs: list[dict]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    tmp.replace(path)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _append(path: Path, rec: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class LabelWindow:

    FIND_BATCH = 200
    FILTERS = ("All scans", "Not complete")
    MAX_SCALE = 2.0
    ZOOM_STEP = 1.25

    def __init__(self, tk_root, base: Path, store: Store):
        import tkinter as tk
        from tkinter import messagebox, ttk

        from .ocr.orientation import needed_rotation

        self.tk, self.store, self.detect, self.confirm = tk_root, store, needed_rotation, messagebox.askyesno
        self.mac = sys.platform == "darwin"
        self.mod, self.accel, self.mod_mask = ("Command", "Cmd", 0x8) if self.mac else ("Control", "Ctrl", 0x4)
        self.files: list[Path] = []
        self.shown: list[Path] = []
        self.file = self.page_img = self.straight = self.photo = None
        self.page = self.pages = 0
        self.detected = self.final = 0.0
        self.rotations: dict[int, tuple[float, float]] = {}
        self.found: list[dict] = []
        self.selected: dict | None = None
        self.editing: dict | None = None
        self.filled: tuple = ("", ())
        self.canvas_size = None
        self.scale, self.zoom = 1.0, 1.0
        self.box = self.drag_start = self.rect = self.resize_job = None
        self.undo_ids: list[str] = []
        self.note = ""
        self.token, self.busy, self.polling, self.walking = 0, False, False, False
        self.requests: queue.Queue = queue.Queue()
        self.results: queue.Queue = queue.Queue()
        self.counts: dict[str, int] = {}
        for rec in store.labels():
            self.counts[rec["source"]] = self.counts.get(rec["source"], 0) + 1
        self.done = store.completed()

        width, height = tk_root.winfo_screenwidth(), tk_root.winfo_screenheight()
        tk_root.geometry(f"{max(900, width - 40)}x{max(560, height - 140)}+10+10")
        tk_root.minsize(900, 560)
        tk_root.report_callback_exception = self._callback_error
        tk_root.protocol("WM_DELETE_WINDOW", self.close)
        self._menus(tk)

        left = ttk.Frame(tk_root, padding=4)
        left.pack(side="left", fill="y")
        self.progress_label = ttk.Label(left, text="Scans")
        self.progress_label.pack(anchor="w")
        self.filter_var = tk.StringVar(value=self.FILTERS[0])
        ttk.Combobox(left, textvariable=self.filter_var, values=self.FILTERS, state="readonly", width=22).pack(fill="x")
        find = ttk.Frame(left)
        find.pack(fill="x", pady=2)
        ttk.Label(find, text="Find").pack(side="left")
        self.search_var = tk.StringVar()
        self.search = ttk.Entry(find, textvariable=self.search_var, width=18)
        self.search.pack(side="left", fill="x", expand=True)
        files = ttk.Frame(left)
        files.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(files, width=24, height=10, exportselection=False)
        list_scroll = ttk.Scrollbar(files, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=list_scroll.set)
        list_scroll.pack(side="right", fill="y")
        self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self._pick)
        self.filter_var.trace_add("write", lambda *_: self.refresh_list())
        self.search_var.trace_add("write", lambda *_: self.refresh_list())

        right = ttk.Frame(tk_root, padding=4)
        right.pack(side="right", fill="y")
        head = ttk.Frame(right)
        head.pack(fill="x")
        ttk.Label(head, text="Types (tick all that apply)").pack(side="left")
        ttk.Button(head, text="+ Add type", command=self.ask_type).pack(side="right")
        holder = ttk.Frame(right)
        holder.pack(fill="both", expand=True)
        self.type_canvas = tk.Canvas(holder, width=240, highlightthickness=0)
        scroll = ttk.Scrollbar(holder, orient="vertical", command=self.type_canvas.yview)
        self.type_canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.type_canvas.pack(side="left", fill="both", expand=True)
        self.type_frame = ttk.Frame(self.type_canvas)
        self.type_canvas.create_window(0, 0, window=self.type_frame, anchor="nw")
        self.type_frame.bind("<Configure>", lambda e: self.type_canvas.configure(
            scrollregion=self.type_canvas.bbox("all"), width=self.type_frame.winfo_reqwidth()))
        tk_root.bind_all("<MouseWheel>", self._wheel)
        self.type_vars: dict = {}
        self.build_types()
        ttk.Label(right, text="Exactly what it says").pack(anchor="w", pady=(4, 0))
        self.text_var = tk.StringVar()
        self.entry = ttk.Entry(right, textvariable=self.text_var, width=32)
        self.entry.pack(anchor="w")
        self.hand_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right, text="Handwritten", variable=self.hand_var).pack(anchor="w")
        ttk.Button(right, text="Save label (Enter)", command=self.save).pack(fill="x", pady=(2, 0))
        ttk.Button(right, text="Delete label", command=self.delete).pack(fill="x")
        ttk.Button(right, text="Bypass: company info", command=self.bypass).pack(fill="x")
        ttk.Button(right, text="Your types & bypass list…", command=self.manage).pack(fill="x", pady=(0, 6))
        ttk.Button(right, text="Next document ▶", command=self.next_document).pack(fill="x")
        ttk.Button(right, text="Complete ✓", command=self.complete).pack(fill="x", pady=2)

        middle = ttk.Frame(tk_root, padding=4)
        middle.pack(side="left", fill="both", expand=True)
        bar = ttk.Frame(middle)
        bar.pack(fill="x")
        ttk.Button(bar, text="◀ Page", width=7, command=lambda: self.go_page(-1)).pack(side="left")
        ttk.Button(bar, text="Page ▶", width=7, command=lambda: self.go_page(1)).pack(side="left")
        ttk.Label(bar, text=" Rotate:").pack(side="left")
        for text, delta in (("⟲90°", 90), ("⟳90°", -90), ("−0.5°", -0.5), ("+0.5°", 0.5)):
            ttk.Button(bar, text=text, width=6, command=lambda d=delta: self.turn(d)).pack(side="left")
        info = ttk.Frame(middle)
        info.pack(fill="x")
        self.page_label = ttk.Label(info, text="no file")
        self.page_label.pack(side="left")
        self.angle_label = ttk.Label(info, text="")
        self.angle_label.pack(side="left", padx=8)
        for text, factor in (("+", self.ZOOM_STEP), ("Fit", None), ("−", 1 / self.ZOOM_STEP)):
            ttk.Button(info, text=text, width=4, command=lambda f=factor: self.zoom_by(f)).pack(side="right")
        self.zoom_label = ttk.Label(info, text="Zoom: fit")
        self.zoom_label.pack(side="right", padx=4)
        page = ttk.Frame(middle)
        page.pack(fill="both", expand=True)
        page.rowconfigure(0, weight=1)
        page.columnconfigure(0, weight=1)
        self.canvas = tk.Canvas(page, width=400, height=300, bg="gray20", cursor="crosshair", highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vbar = ttk.Scrollbar(page, orient="vertical", command=self.canvas.yview)
        hbar = ttk.Scrollbar(page, orient="horizontal", command=self.canvas.xview)
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        self.canvas.configure(xscrollcommand=hbar.set, yscrollcommand=vbar.set)
        self.canvas.bind("<ButtonPress-1>", self.press)
        self.canvas.bind("<B1-Motion>", self.drag)
        self.canvas.bind("<ButtonRelease-1>", self.release)
        self.canvas.bind("<Configure>", self.resized)
        foot = ttk.Frame(middle)
        foot.pack(fill="x")
        self.progress = ttk.Progressbar(foot, mode="indeterminate", length=120)
        self.progress.pack(side="right")
        self.status = ttk.Label(foot, text="Looking for scans…", wraplength=600)
        self.status.pack(side="left", fill="x", expand=True)

        tk_root.bind("<Return>", lambda e: e.widget is not self.search and self.save())
        tk_root.bind("<Escape>", lambda e: self.clear_box())
        tk_root.bind("<Prior>", lambda e: self.go_page(-1))
        tk_root.bind("<Next>", lambda e: self.go_page(1))
        tk_root.bind("<Delete>", self._key_delete)
        tk_root.bind("<BackSpace>", self._key_delete)
        for keys, action in ((("z",), self.undo), (("Right",), self.next_document), (("Return",), self.complete),
                             (("equal", "plus"), lambda: self.zoom_by(self.ZOOM_STEP)),
                             (("minus",), lambda: self.zoom_by(1 / self.ZOOM_STEP)), (("Key-0",), lambda: self.zoom_by(None)),
                             (("o",), self.open_folder), *([] if self.mac else [(("q",), self.close)])):
            for key in keys:
                tk_root.bind(f"<{self.mod}-{key}>", lambda e, a=action: a())
        threading.Thread(target=self._work, daemon=True).start()
        self.load_folder(base)

    def _menus(self, tk):
        bar = tk.Menu(self.tk)
        a = self.accel
        menus = [
            ("File", [("Open folder…", self.open_folder, f"{a}+O"), None, ("Quit", self.close, f"{a}+Q")]),
            ("Label", [("Save label", self.save, "Enter"), ("Delete label", self.delete, "Delete"),
                       ("Undo last label", self.undo, f"{a}+Z"), None, ("Bypass company info", self.bypass, "")]),
            ("Types", [("Add type…", self.ask_type, ""), ("Your types & bypass list…", self.manage, "")]),
            ("View", [("Zoom in", lambda: self.zoom_by(self.ZOOM_STEP), f"{a}+="),
                      ("Zoom out", lambda: self.zoom_by(1 / self.ZOOM_STEP), f"{a}+-"),
                      ("Fit page", lambda: self.zoom_by(None), f"{a}+0")]),
            ("Go", [("Previous page", lambda: self.go_page(-1), "PgUp"), ("Next page", lambda: self.go_page(1), "PgDn"),
                    None, ("Next document", self.next_document, f"{a}+→"), ("Complete", self.complete, f"{a}+Return")]),
            ("Help", [("Keyboard shortcuts", self.show_shortcuts, "")]),
        ]
        for title, items in menus:
            menu = tk.Menu(bar, tearoff=0)
            for item in items:
                if item is None:
                    menu.add_separator()
                else:
                    menu.add_command(label=item[0], command=item[1], accelerator=item[2])
            bar.add_cascade(label=title, menu=menu)
        self.tk.config(menu=bar)
        if self.mac:
            try:
                self.tk.createcommand("::tk::mac::Quit", self.close)
            except tk.TclError:
                pass

    def shortcuts(self) -> list[tuple[str, str]]:
        a = self.accel
        return [("Enter", "save the label"), ("Esc", "clear the box"), ("PgUp / PgDn", "previous / next page"),
                (f"{a}+Z", "undo the last label you saved"), ("Delete", "delete the selected saved label"),
                (f"{a}+→", "next document"), (f"{a}+Return", "complete the document"),
                (f"{a}+= / {a}+- / {a}+0", "zoom in / out / fit"), (f"{a}+wheel", "zoom at the pointer"),
                ("Wheel / Shift+wheel", "scroll the page"), (f"{a}+O", "open another folder")]

    def show_shortcuts(self):
        from tkinter import messagebox

        messagebox.showinfo("Keyboard shortcuts", "\n".join(f"{k}: {v}" for k, v in self.shortcuts()), parent=self.tk)

    def _callback_error(self, exc_type, exc, tb):
        self.status.config(text=f"Something went wrong ({describe(exc)}). You can keep going; check that your last "
                                "change took effect.")

    def load_folder(self, base: Path):
        self.base = base
        self.files, self.shown = [], []
        self.pending, self.walking = scan_files(base), True
        self.token += 1
        self.busy = False
        self.progress.stop()
        self.file = self.page_img = self.straight = None
        self.page = self.pages = 0
        self.found = []
        self.clear_box()
        self.canvas.delete("all")
        self.listbox.delete(0, "end")
        self.page_label.config(text="no file")
        self.angle_label.config(text="")
        self.tk.title(f"piiscan labeling – {base.name or base}")
        self.status.config(text="Looking for scans…")
        self.tk.after(1, self.find_more)

    def open_folder(self):
        from tkinter import filedialog

        if not self._leave_ok():
            return
        chosen = filedialog.askdirectory(title="Choose the folder of scans to label", mustexist=True,
                                         initialdir=str(self.base), parent=self.tk)
        if chosen:
            self.load_folder(Path(chosen))

    def close(self):
        if self._leave_ok():
            self.requests.put(None)
            self.tk.destroy()

    def wait_idle(self, timeout: float = 300):
        end = time.monotonic() + timeout
        while self.busy or self.walking:
            if time.monotonic() > end:
                raise TimeoutError("the labeling window stayed busy")
            self.tk.update()
            time.sleep(0.01)

    def find_more(self):
        batch = list(islice(self.pending, self.FIND_BATCH))
        for p in batch:
            self.files.append(p)
            if self._matches(p):
                self.shown.append(p)
                self.listbox.insert("end", self.row(p))
        if len(batch) == self.FIND_BATCH:
            self._progress()
            self.tk.after(1, self.find_more)
            return
        self.walking = False
        self._progress()
        left = sum(str(p) not in self.done for p in self.files)
        self.status.config(text=f"{len(self.files)} scans found, {left} not complete. Pick one to start."
                           if self.files else "No scans (PDF, TIFF, JPG, PNG, HEIC) in this folder.")

    def row(self, p: Path) -> str:
        n = self.counts.get(str(p), 0)
        return ("✓ " if str(p) in self.done else "   ") + f"{p.relative_to(self.base)}" + (f"  [{n}]" if n else "")

    def _matches(self, p: Path) -> bool:
        if self.filter_var.get() == self.FILTERS[1] and str(p) in self.done:
            return False
        return self.search_var.get().strip().lower() in str(p.relative_to(self.base)).lower()

    def _progress(self):
        done = sum(str(p) in self.done for p in self.files)
        text = f"{done} of {len(self.files)} complete" + (" (still looking…)" if self.walking else "")
        if len(self.shown) != len(self.files):
            text += f", showing {len(self.shown)}"
        self.progress_label.config(text=text)

    def refresh_list(self):
        self.shown = [p for p in self.files if self._matches(p)]
        self.listbox.delete(0, "end")
        for p in self.shown:
            self.listbox.insert("end", self.row(p))
        self._select_current()
        self._progress()

    def _select_current(self):
        self.listbox.selection_clear(0, "end")
        if self.file in self.shown:
            index = self.shown.index(self.file)
            self.listbox.selection_set(index)
            self.listbox.see(index)

    def _update_row(self, p: Path | None):
        if p in self.shown:
            index = self.shown.index(p)
            self.listbox.delete(index)
            self.listbox.insert(index, self.row(p))
            self._select_current()

    def _pick(self, _event=None):
        chosen = self.listbox.curselection()
        if not chosen or self.shown[chosen[0]] == self.file:
            return
        if self._leave_ok():
            self.open_file(self.files.index(self.shown[chosen[0]]))
        else:
            self._select_current()

    def build_types(self, ticked=()):
        import tkinter as tk
        from tkinter import ttk

        for child in self.type_frame.winfo_children():
            child.destroy()
        self.names = self.store.rules.names()
        self.type_vars = {name: tk.BooleanVar(value=name in ticked) for name in self.names}
        for name, var in self.type_vars.items():
            row = ttk.Frame(self.type_frame)
            row.pack(anchor="w")
            tk.Label(row, text="■", fg=self.store.rules.color(self.names[name])).pack(side="left")
            ttk.Checkbutton(row, text=name, variable=var, command=lambda n=name: self.ticked(n)).pack(side="left")

    def _wheel(self, e):
        try:
            under = str(self.tk.winfo_containing(e.x_root, e.y_root) or "")
        except KeyError:
            return
        step = -1 if e.delta > 0 else 1
        if under.startswith(str(self.type_canvas)):
            self.type_canvas.yview_scroll(step, "units")
        elif under == str(self.canvas) and self.straight is not None:
            if e.state & self.mod_mask:
                at = (e.x_root - self.canvas.winfo_rootx(), e.y_root - self.canvas.winfo_rooty())
                self.zoom_by(self.ZOOM_STEP if e.delta > 0 else 1 / self.ZOOM_STEP, at)
            elif e.state & 0x1:
                self.canvas.xview_scroll(step, "units")
            else:
                self.canvas.yview_scroll(step, "units")

    def ticked(self, name: str):
        if not self.type_vars[name].get():
            return
        for other, var in self.type_vars.items():
            if (name == NONE) != (other == NONE):
                var.set(False)

    def _ticks(self) -> tuple:
        return tuple(n for n, v in self.type_vars.items() if v.get())

    def _unsaved(self) -> bool:
        text = self.text_var.get().strip()
        return bool(self.box and text and (text, self._ticks()) != self.filled)

    def _leave_ok(self) -> bool:
        return not self._unsaved() or bool(self.confirm(
            "Unsaved label", "The box you're working on isn't saved. Leave it without saving?", parent=self.tk))

    def _ready(self) -> bool:
        if self.busy:
            self.status.config(text="Still reading the page; one moment…")
        return not self.busy and self.straight is not None

    def ask_type(self):
        import tkinter as tk
        from tkinter import ttk

        win = tk.Toplevel(self.tk)
        win.title("Add a type")
        win.transient(self.tk)
        group, name, words = tk.StringVar(value="CPNI"), tk.StringVar(), tk.StringVar()
        fields = [("Group", ttk.Combobox(win, textvariable=group, values=GROUPS, state="readonly", width=30)),
                  ("Name", ttk.Entry(win, textvariable=name, width=32)),
                  ("Words printed next to it on forms\n(comma-separated; blank = the name)",
                   ttk.Entry(win, textvariable=words, width=32))]
        for row, (text, widget) in enumerate(fields):
            ttk.Label(win, text=text).grid(row=row, column=0, sticky="w", padx=6, pady=3)
            widget.grid(row=row, column=1, padx=6, pady=3)
        note = ttk.Label(win, text="")
        note.grid(row=3, column=0, columnspan=2, sticky="w", padx=6)

        def add():
            try:
                self.add_type(group.get(), name.get(), words.get())
            except ValueError as e:
                note.config(text=str(e))
                return
            win.destroy()

        buttons = ttk.Frame(win)
        buttons.grid(row=4, column=1, sticky="e", padx=6, pady=6)
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side="right")
        ttk.Button(buttons, text="Add", command=add).pack(side="right", padx=4)
        win.bind("<Return>", lambda e: add())
        win.bind("<Escape>", lambda e: win.destroy())
        fields[1][1].focus_set()

    def add_type(self, group: str, name: str, words: str = "") -> dict:
        rec = self.store.rules.add_type(group, name, words)
        self.build_types({n for n, v in self.type_vars.items() if v.get()} - {NONE} | {f"{rec['group']}: {rec['name']}"})
        self.status.config(text=f"Added {rec['code']}. Scans now look for it after: {', '.join(rec['words'])}. "
                                "Run `scan --full` once to look in files that were already scanned.")
        return rec

    def remove_type(self, code: str) -> str:
        used = sum(code in label_types(r) for r in self.store.labels())
        if used:
            return f"{used} saved label(s) use this type: change or delete them first."
        self.store.rules.remove_type(code)
        self.build_types({n for n, v in self.type_vars.items() if v.get()})
        return "Type removed."

    def bypass(self):
        codes = [self.names[n] for n, v in self.type_vars.items() if v.get()]
        if not codes and self.selected:
            codes = [self.selected["type"]]
        also = [(self.selected["type"], self.selected["value"])] if self.selected else []
        rules = self.store.rules
        try:
            rec = rules.add_bypass(codes, self.text_var.get(), also)
        except ValueError as e:
            self.status.config(text=str(e))
            return
        self.found = [f for f in self.found if not rules.skips(f["type"], f["value"])]
        self.clear_box()
        self.text_var.set("")
        if self.straight is not None:
            self.render()
        self.status.config(text=f"Bypassed everywhere: {rec['value']} ({', '.join(rec['types'])}). It no longer counts "
                                f"in scans or totals. {len(rules.bypass)} on the bypass list.")

    def manage(self):
        import tkinter as tk
        from tkinter import ttk

        rules = self.store.rules
        win = tk.Toplevel(self.tk)
        win.title("Your types & bypass list")
        win.transient(self.tk)
        ttk.Label(win, text="Types you added").grid(row=0, column=0, sticky="w", padx=6)
        ttk.Label(win, text="Bypassed everywhere (company info)").grid(row=0, column=1, sticky="w", padx=6)
        types = tk.Listbox(win, width=40, height=12, exportselection=False)
        passes = tk.Listbox(win, width=44, height=12, exportselection=False)
        types.grid(row=1, column=0, padx=6)
        passes.grid(row=1, column=1, padx=6)
        note = ttk.Label(win, text="", wraplength=640)
        note.grid(row=3, column=0, columnspan=2, sticky="w", padx=6, pady=(0, 6))

        def fill():
            types.delete(0, "end")
            passes.delete(0, "end")
            for t in rules.types:
                types.insert("end", f"{t['group']}: {t['name']}  (after: {', '.join(t['words'])})")
            for b in rules.bypass:
                passes.insert("end", f"{b['value']}  ({', '.join(b['types'])})")

        def drop_type():
            if types.curselection():
                t = rules.types[types.curselection()[0]]
                if self.confirm("Remove type", f"Remove the type {t['group']}: {t['name']}?", parent=win):
                    note.config(text=self.remove_type(t["code"]))
                    fill()

        def drop_bypass():
            if passes.curselection():
                index = passes.curselection()[0]
                if self.confirm("Remove from bypass list", f"Count {rules.bypass[index]['value']} again?", parent=win):
                    rules.remove_bypass(index)
                    note.config(text="Removed: that value counts again from the next scan or totals.")
                    fill()

        ttk.Button(win, text="Remove type", command=drop_type).grid(row=2, column=0, sticky="w", padx=6, pady=4)
        ttk.Button(win, text="Remove from bypass list", command=drop_bypass).grid(row=2, column=1, sticky="w", padx=6, pady=4)
        ttk.Button(win, text="Close", command=win.destroy).grid(row=4, column=1, sticky="e", padx=6, pady=6)
        win.bind("<Escape>", lambda e: win.destroy())
        fill()

    def open_file(self, index: int):
        self.file = self.files[index]
        self.rotations = {}
        try:
            self.pages = page_count(self.file)
        except Exception:
            self.pages = 0
            self.token += 1
            self.busy = False
            self.progress.stop()
            self.page_img = self.straight = None
            self.clear_box()
            self.canvas.delete("all")
            self.refresh_list()
            self.status.config(text="Can't open this file (password-protected or damaged). Use Next document.")
            return
        self.refresh_list()
        self.page = 1
        self.open_page()

    def next_document(self):
        index = self.shown.index(self.file) + 1 if self.file in self.shown else 0
        if index >= len(self.shown):
            self.status.config(text="That was the last document.")
            return
        if self._leave_ok():
            self.open_file(self.files.index(self.shown[index]))

    def complete(self):
        if not self.file or not self.pages:
            self.status.config(text="Open a document first.")
            return
        if not self._leave_ok():
            return
        self.store.complete(self.file, self.pages, self.rotations)
        self.done.add(str(self.file))
        start = self.files.index(self.file)
        for index in [*range(start + 1, len(self.files)), *range(0, start)]:
            if str(self.files[index]) not in self.done:
                self.note = f"Marked complete: {len(self.done)} of {len(self.files)} done. "
                self.open_file(index)
                return
        self.refresh_list()
        self.status.config(text=f"All {len(self.files)} documents are complete.")

    def go_page(self, step: int):
        if self.file and 1 <= self.page + step <= self.pages and self._leave_ok():
            self.page += step
            self.open_page()

    def open_page(self):
        self._read(None)

    def turn(self, delta: float):
        if self.page_img is not None and self._ready() and self._leave_ok():
            self.set_rotation(round(((self.final + delta + 180) % 360) - 180, 1))

    def set_rotation(self, angle: float):
        self._read(angle)

    def _read(self, angle: float | None):
        self.clear_box()
        self.token += 1
        image = self.page_img if angle is not None else None
        self.page_img = image
        self.straight = None
        self.found = []
        self.busy = True
        self.progress.start(15)
        self.canvas.delete("all")
        self.canvas.create_text(max(self.canvas.winfo_width(), 200) / 2, 40, text="Reading the page…", fill="white")
        self.status.config(text="Straightening and reading the page…")
        self.requests.put((self.token, self.file, self.page, image, angle, self.store.rules))
        if not self.polling:
            self.polling = True
            self.tk.after(30, self._poll)

    def _work(self):
        while True:
            job = self.requests.get()
            if job is None:
                return
            token, file, page, image, angle, rules = job
            if token != self.token:
                continue
            try:
                image = image if image is not None else load_page(file, page)
                detected = self.detect(image) if angle is None else None
                final = detected if angle is None else angle
                straight = image.rotate(final, expand=True, fillcolor="white")
                found = suggestions(straight, page, rules) if token == self.token else []
                self.results.put((token, None, (image, detected, final, straight, found)))
            except Exception as e:
                self.results.put((token, e, None))

    def _poll(self):
        while True:
            try:
                token, error, result = self.results.get_nowait()
            except queue.Empty:
                break
            if token == self.token:
                self._loaded(error, result)
        if self.busy:
            self.tk.after(30, self._poll)
        else:
            self.polling = False

    def _loaded(self, error, result):
        self.busy = False
        self.progress.stop()
        note, self.note = self.note, ""
        if error is not None:
            self.canvas.delete("all")
            self.status.config(text=f"{note}Couldn't read this page ({describe(error)}). Try Next document.")
            return
        image, detected, final, straight, found = result
        rules = self.store.rules
        self.page_img, self.final, self.straight = image, final, straight
        if detected is not None:
            self.detected = detected
        self.rotations[self.page] = (self.detected, self.final)
        self.found = [f for f in found if not rules.skips(f["type"], f["value"])]
        self.render()
        self.canvas.xview_moveto(0)
        self.canvas.yview_moveto(0)
        self.status.config(text=f"{note}{len(self.visible())} found by the scanner (dashed): click one to confirm or "
                                "correct it, or drag a box around one line.")

    def saved_here(self) -> list[dict]:
        return [r for r in self.store.labels()
                if r["source"] == str(self.file) and r["page"] == self.page and r["rotation_final"] == self.final]

    def visible(self) -> list[dict]:
        saved = [r["box"] for r in self.saved_here()]
        return [f for f in self.found if not any(overlap(f["box"], b) for b in saved)]

    def resized(self, _event=None):
        size = (self.canvas.winfo_width(), self.canvas.winfo_height())
        if self.straight is None or size == self.canvas_size:
            return
        self.canvas_size = size
        if self.resize_job:
            self.tk.after_cancel(self.resize_job)
        self.resize_job = self.tk.after(150, self.render)

    def zoom_by(self, factor: float | None, at: tuple[float, float] | None = None):
        if not self._ready():
            return
        ax, ay = at or (self.canvas.winfo_width() / 2, self.canvas.winfo_height() / 2)
        ix, iy = self.canvas.canvasx(ax) / self.scale, self.canvas.canvasy(ay) / self.scale
        self.zoom = 1.0 if factor is None else max(1.0, self.zoom * factor)
        self.render()
        width, height = self.straight.width * self.scale, self.straight.height * self.scale
        self.canvas.xview_moveto(max(0.0, (ix * self.scale - ax) / width))
        self.canvas.yview_moveto(max(0.0, (iy * self.scale - ay) / height))

    def render(self):
        from PIL import ImageTk

        self.resize_job = None
        if self.straight is None:
            return
        width, height = max(self.canvas.winfo_width(), 200), max(self.canvas.winfo_height(), 200)
        fit = min(width / self.straight.width, height / self.straight.height)
        self.zoom = min(self.zoom, max(1.0, self.MAX_SCALE / fit))
        self.scale = fit * self.zoom
        size = (max(1, int(self.straight.width * self.scale)), max(1, int(self.straight.height * self.scale)))
        self.photo = ImageTk.PhotoImage(self.straight.resize(size))
        self.canvas.delete("all")
        self.canvas.create_image(0, 0, image=self.photo, anchor="nw")
        self.canvas.configure(scrollregion=(0, 0, *size))
        for rec in self.saved_here():
            self._draw_box(rec["box"], label_types(rec), ", ".join(label_types(rec)), dash=None)
        for f in self.visible():
            self._draw_box(f["box"], [f["type"]], f"{f['type']} ?", dash=(5, 3))
        self.rect = None
        if self.box:
            self._outline_selection()
        done = "  ✓ complete" if str(self.file) in self.done else ""
        self.page_label.config(text=f"{self.file.name}  {self.page}/{self.pages}{done}")
        self.angle_label.config(text=f"detected {self.detected:+.1f}°, using {self.final:+.1f}°")
        self.zoom_label.config(text="Zoom: fit" if self.zoom == 1 else f"Zoom: {self.zoom:.0%}")

    def _draw_box(self, box, codes: list[str], caption: str, dash):
        color = self.store.rules.color(codes[0])
        x0, y0, x1, y1 = (v * self.scale for v in self._px(box))
        self.canvas.create_rectangle(x0, y0, x1, y1, outline=color, width=2, dash=dash)
        self.canvas.create_text(x0, y0 - 2, text=caption, anchor="sw", fill=color)

    def _px(self, box) -> tuple[int, int, int, int]:
        x0, y0, x1, y1 = box
        w, h = self.straight.width, self.straight.height
        return int(x0 * w), int(y0 * h), int(x1 * w) + 1, int(y1 * h) + 1

    def _xy(self, e) -> tuple[float, float]:
        return self.canvas.canvasx(e.x), self.canvas.canvasy(e.y)

    def _outline_selection(self):
        s = self.scale
        x0, y0, x1, y1 = self.box
        self.rect = self.canvas.create_rectangle(x0 * s, y0 * s, x1 * s, y1 * s, outline="red", width=3)

    def _hit(self, box, x: float, y: float, margin: int = 6) -> bool:
        x0, y0, x1, y1 = (v * self.scale for v in self._px(box))
        return x0 - margin <= x <= x1 + margin and y0 - 18 <= y <= y1 + margin

    def press(self, e):
        if not self._ready():
            return
        self.clear_box()
        x, y = self._xy(e)
        for f in self.visible():
            if self._hit(f["box"], x, y):
                return self.select(f)
        for rec in self.saved_here():
            if self._hit(rec["box"], x, y):
                return self.edit(rec)
        self.drag_start = (x, y)
        self.filled = ("", self._ticks())

    def select(self, found: dict):
        self.selected, self.box = found, self._px(found["box"])
        self._fill([found["type"]], found["text"], self.hand_var.get())
        self._outline_selection()
        self.status.config(text=f"Scanner found {found['type']}. Change the types or text if wrong (None if not "
                                "sensitive), then Enter. Company info? Bypass it.")

    def edit(self, rec: dict):
        self.editing, self.box = rec, self._px(rec["box"])
        self._fill(label_types(rec), rec["text"], rec["handwritten"])
        self._outline_selection()
        self.status.config(text="Editing a saved label: change the types or text, then Enter. Or press Delete label.")

    def _fill(self, codes: list[str], text: str, handwritten: bool):
        for name, var in self.type_vars.items():
            var.set(self.names[name] in codes)
        self.text_var.set(text)
        self.hand_var.set(handwritten)
        self.filled = (text.strip(), self._ticks())
        self.entry.focus_set()

    def drag(self, e):
        if self.drag_start:
            if self.rect:
                self.canvas.delete(self.rect)
            self.rect = self.canvas.create_rectangle(*self.drag_start, *self._xy(e), outline="red", width=2)

    def release(self, e):
        if not (self.drag_start and self.straight):
            return
        (ax, ay), (bx, by), s = self.drag_start, self._xy(e), self.scale
        x0, x1 = sorted((ax, bx))
        y0, y1 = sorted((ay, by))
        self.box = (max(0, int(x0 / s)), max(0, int(y0 / s)),
                    min(self.straight.width, int(x1 / s)), min(self.straight.height, int(y1 / s)))
        self.drag_start = None
        self.entry.focus_set()

    def clear_box(self):
        if self.rect:
            self.canvas.delete(self.rect)
        self.box = self.drag_start = self.rect = self.selected = self.editing = None
        self.filled = ("", ())

    def _key_delete(self, e):
        if e.widget.winfo_class() not in ("Entry", "TEntry", "TCombobox", "Text") and self.editing:
            self.delete()

    def save(self):
        if not self._ready():
            return
        if not self.box:
            self.status.config(text="Click a box or drag your own first.")
            return
        ticked = [name for name, var in self.type_vars.items() if var.get()]
        try:
            if self.editing:
                self.store.update(self.editing["id"], ticked, self.text_var.get(), self.hand_var.get())
                message = "Label updated."
            else:
                suggested = self.selected["type"] if self.selected else None
                rec = self.store.save(self.file, self.page, self.straight, self.box, ticked, self.text_var.get(),
                                      self.hand_var.get(), self.detected, self.final, suggested)
                self.undo_ids.append(rec["id"])
                self.counts[str(self.file)] = self.counts.get(str(self.file), 0) + 1
                corrected = suggested and [self.names[n] for n in ticked] != [suggested]
                message = "Saved your correction." if corrected else "Saved."
        except ValueError as e:
            self.status.config(text=str(e))
            return
        self._after_change(message, self.file)

    def delete(self):
        if not self._ready():
            return
        if not self.editing:
            self.status.config(text="Click a saved (solid) box first, then Delete label.")
            return
        self.store.delete(self.editing["id"])
        self.counts[str(self.file)] = max(0, self.counts.get(str(self.file), 0) - 1)
        self._after_change("Label deleted.", self.file)

    def undo(self):
        saved = {r["id"]: r for r in self.store.labels()}
        while self.undo_ids and self.undo_ids[-1] not in saved:
            self.undo_ids.pop()
        if not self.undo_ids:
            self.status.config(text="Nothing to undo.")
            return
        rec = saved[self.undo_ids.pop()]
        self.store.delete(rec["id"])
        self.counts[rec["source"]] = max(0, self.counts.get(rec["source"], 0) - 1)
        self._after_change(f"Undid your last label (page {rec['page']} of {Path(rec['source']).name}).",
                           Path(rec["source"]))

    def _after_change(self, message: str, source: Path | None):
        self.clear_box()
        self.text_var.set("")
        if self.straight is not None and not self.busy:
            self.render()
        self._update_row(source)
        self.status.config(text=f"{message} {sum(self.counts.values())} labels in total; "
                                f"{len(self.visible())} suggestions left here.")


def run(root: Path | None, store_dir: Path = TRAINING_DIR, rules_path: Path = RULES_PATH) -> None:
    import tkinter as tk
    from tkinter import filedialog

    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            pass
    tk_root = tk.Tk()
    if root is None:
        tk_root.withdraw()
        chosen = filedialog.askdirectory(title="Choose the folder of scans to label", mustexist=True)
        if not chosen:
            tk_root.destroy()
            return
        root = Path(chosen)
        tk_root.deiconify()
    LabelWindow(tk_root, root, Store(store_dir, Rules(rules_path)))
    tk_root.lift()
    tk_root.attributes("-topmost", True)
    tk_root.after(500, lambda: tk_root.attributes("-topmost", False))
    tk_root.focus_force()
    tk_root.mainloop()
