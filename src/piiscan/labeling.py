import getpass
import json
import os
import uuid
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

from . import db

TRAINING_DIR = db.PROJECT_DIR / "data" / "training"
SCAN_EXTS = {".pdf", ".tif", ".tiff", ".jpg", ".jpeg", ".png", ".heic"}
RENDER_SCALE = 300 / 72
NONE = "None (no sensitive data)"
LABEL_TYPES = {
    "Identification: Driver's license": "DRIVERS_LICENSE",
    "Identification: State ID": "STATE_ID",
    "Identification: Passport": "PASSPORT",
    "SSN": "SSN",
    "Bank info: Bank account #": "BANK_ACCOUNT",
    "Bank info: Routing #": "ROUTING_NUMBER",
    "Bank info: Card #": "CARD_NUMBER",
    "CPNI: Customer account #": "CUSTOMER_ACCOUNT",
    "CPNI: Phone #": "PHONE_NUMBER",
    "CPNI: Call detail": "CALL_DETAIL",
    "CPNI: Services / plan": "SERVICE_PLAN",
    "CPNI: Billing amount": "BILLING_AMOUNT",
    "Other: Date of birth": "DATE_OF_BIRTH",
    "Other: Name": "PERSON_NAME",
    "Other: Address": "ADDRESS",
    "Other: Email": "EMAIL",
    "Other: ITIN": "ITIN",
    "Other: Password / PIN": "CREDENTIAL",
    NONE: "NONE",
}
CODE_TO_NAME = {code: name for name, code in LABEL_TYPES.items()}
COLORS = {
    "SSN": "#d62728", "ITIN": "#8b0000", "DRIVERS_LICENSE": "#1f77b4", "STATE_ID": "#00a0b0", "PASSPORT": "#6a3d9a",
    "BANK_ACCOUNT": "#2ca02c", "ROUTING_NUMBER": "#006400", "CARD_NUMBER": "#ff7f0e", "CUSTOMER_ACCOUNT": "#e6007e",
    "PHONE_NUMBER": "#8c564b", "CALL_DETAIL": "#b8860b", "SERVICE_PLAN": "#808000", "BILLING_AMOUNT": "#4682b4",
    "DATE_OF_BIRTH": "#ff1493", "PERSON_NAME": "#9932cc", "ADDRESS": "#008b8b", "EMAIL": "#556b2f",
    "CREDENTIAL": "#000000", "NONE": "#7f7f7f",
}
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


def suggestions(straight, page: int) -> list[dict]:
    import numpy as np

    from .detect import detect
    from .ocr.engine import read_upright

    found = []
    for span in read_upright(np.asarray(straight), page):
        for pii_type, start, end, _, conf, _ in detect(span.text, span.header):
            _, box, ocr_conf = span.where(start, end)
            if box:
                found.append({"type": pii_type, "box": box, "text": span.text[start:end], "source": span.source,
                              "confidence": round(conf * (0.5 + 0.5 * ocr_conf), 3)})
    kept: list[dict] = []
    for f in sorted(found, key=lambda f: (f["source"] != "ocr_hand", -f["confidence"])):
        if not any(g["type"] == f["type"] and g["source"] != f["source"] and overlap(g["box"], f["box"]) for g in kept):
            kept.append(f)
    return kept


def overlap(a, b) -> bool:
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


class Store:

    def __init__(self, root: Path = TRAINING_DIR):
        self.root = root
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
        _check(labels, text)
        if x1 - x0 < MIN_BOX or y1 - y0 < MIN_BOX:
            raise ValueError("box is too small")
        rec = {
            "id": uuid.uuid4().hex, "source": str(source), "page": page, "types": [LABEL_TYPES[x] for x in labels],
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
        _check(labels, text)
        recs = self.labels()
        rec = next(r for r in recs if r["id"] == label_id)
        rec.update(types=[LABEL_TYPES[x] for x in labels], text=text.strip(), handwritten=handwritten,
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


def _check(labels: list[str], text: str) -> None:
    if not labels:
        raise ValueError("tick at least one type (or None)")
    if any(label not in LABEL_TYPES for label in labels):
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

    def __init__(self, tk_root, base: Path, store: Store):
        import tkinter as tk
        from tkinter import ttk

        from .ocr.orientation import needed_rotation

        self.tk, self.base, self.store, self.detect = tk_root, base, store, needed_rotation
        self.files: list[Path] = []
        self.pending, self.walking = scan_files(base), True
        self.file = self.page_img = self.straight = self.photo = None
        self.page = self.pages = 0
        self.detected = self.final = 0.0
        self.rotations: dict[int, tuple[float, float]] = {}
        self.found: list[dict] = []
        self.selected: dict | None = None
        self.editing: dict | None = None
        self.canvas_size = None
        self.scale = 1.0
        self.box = self.drag_start = self.rect = self.resize_job = None
        self.counts: dict[str, int] = {}
        for rec in store.labels():
            self.counts[rec["source"]] = self.counts.get(rec["source"], 0) + 1
        self.done = store.completed()

        width, height = tk_root.winfo_screenwidth(), tk_root.winfo_screenheight()
        tk_root.geometry(f"{max(900, width - 40)}x{max(560, height - 140)}+10+10")
        tk_root.minsize(900, 560)
        tk_root.title("piiscan labeling")

        left = ttk.Frame(tk_root, padding=4)
        left.pack(side="left", fill="y")
        ttk.Label(left, text="Scans (✓ = complete)").pack(anchor="w")
        self.listbox = tk.Listbox(left, width=24, height=10, exportselection=False)
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>",
                          lambda e: self.listbox.curselection() and self.open_file(self.listbox.curselection()[0]))

        right = ttk.Frame(tk_root, padding=4)
        right.pack(side="right", fill="y")
        ttk.Label(right, text="Types (tick all that apply)").pack(anchor="w")
        self.type_vars = {name: tk.BooleanVar() for name in LABEL_TYPES}
        for name, var in self.type_vars.items():
            row = ttk.Frame(right)
            row.pack(anchor="w")
            tk.Label(row, text="■", fg=COLORS[LABEL_TYPES[name]]).pack(side="left")
            ttk.Checkbutton(row, text=name, variable=var, command=lambda n=name: self.ticked(n)).pack(side="left")
        ttk.Label(right, text="Exactly what it says").pack(anchor="w", pady=(4, 0))
        self.text_var = tk.StringVar()
        self.entry = ttk.Entry(right, textvariable=self.text_var, width=32)
        self.entry.pack(anchor="w")
        self.hand_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right, text="Handwritten", variable=self.hand_var).pack(anchor="w")
        ttk.Button(right, text="Save label (Enter)", command=self.save).pack(fill="x", pady=(2, 0))
        ttk.Button(right, text="Delete label", command=self.delete).pack(fill="x", pady=(0, 6))
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
        self.canvas = tk.Canvas(middle, width=400, height=300, bg="gray20", cursor="crosshair", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<ButtonPress-1>", self.press)
        self.canvas.bind("<B1-Motion>", self.drag)
        self.canvas.bind("<ButtonRelease-1>", self.release)
        self.canvas.bind("<Configure>", self.resized)
        self.status = ttk.Label(middle, text="Looking for scans…", wraplength=600)
        self.status.pack(anchor="w")

        tk_root.bind("<Return>", lambda e: self.save())
        tk_root.bind("<Escape>", lambda e: self.clear_box())
        tk_root.bind("<Prior>", lambda e: self.go_page(-1))
        tk_root.bind("<Next>", lambda e: self.go_page(1))
        tk_root.after(1, self.find_more)

    def find_more(self):
        batch = list(islice(self.pending, self.FIND_BATCH))
        for p in batch:
            self.files.append(p)
            self.listbox.insert("end", self.row(p))
        if len(batch) == self.FIND_BATCH:
            self.tk.after(1, self.find_more)
            return
        self.walking = False
        left = sum(str(p) not in self.done for p in self.files)
        self.status.config(text=f"{len(self.files)} scans found, {left} not complete. Pick one to start."
                           if self.files else "No scans (PDF, TIFF, JPG, PNG, HEIC) in this folder.")

    def row(self, p: Path) -> str:
        n = self.counts.get(str(p), 0)
        return ("✓ " if str(p) in self.done else "   ") + f"{p.relative_to(self.base)}" + (f"  [{n}]" if n else "")

    def refresh_list(self):
        self.listbox.delete(0, "end")
        for p in self.files:
            self.listbox.insert("end", self.row(p))
        if self.file in self.files:
            index = self.files.index(self.file)
            self.listbox.selection_set(index)
            self.listbox.see(index)

    def ticked(self, name: str):
        if not self.type_vars[name].get():
            return
        for other, var in self.type_vars.items():
            if (name == NONE) != (other == NONE):
                var.set(False)

    def open_file(self, index: int):
        self.file = self.files[index]
        self.rotations = {}
        try:
            self.pages = page_count(self.file)
        except Exception:
            self.status.config(text="Can't open this file (password-protected or damaged). Use Next document.")
            return
        self.refresh_list()
        self.page = 1
        self.open_page()

    def next_document(self):
        index = self.files.index(self.file) + 1 if self.file in self.files else 0
        if index >= len(self.files):
            self.status.config(text="That was the last document.")
            return
        self.open_file(index)

    def complete(self):
        if not self.file or not self.pages:
            self.status.config(text="Open a document first.")
            return
        self.store.complete(self.file, self.pages, self.rotations)
        self.done.add(str(self.file))
        start = self.files.index(self.file)
        for index in [*range(start + 1, len(self.files)), *range(0, start)]:
            if str(self.files[index]) not in self.done:
                self.open_file(index)
                self.status.config(text=f"Marked complete. {len(self.done)} documents complete.")
                return
        self.refresh_list()
        self.status.config(text=f"All {len(self.files)} documents are complete.")

    def go_page(self, step: int):
        if self.file and 1 <= self.page + step <= self.pages:
            self.page += step
            self.open_page()

    def open_page(self):
        self.status.config(text="Straightening page…")
        self.tk.update_idletasks()
        self.page_img = load_page(self.file, self.page)
        self.detected = self.detect(self.page_img)
        self.set_rotation(self.detected)

    def turn(self, delta: float):
        if self.page_img is not None:
            self.set_rotation(round(((self.final + delta + 180) % 360) - 180, 1))

    def set_rotation(self, angle: float):
        self.clear_box()
        self.final = angle
        self.rotations[self.page] = (self.detected, self.final)
        self.straight = self.page_img.rotate(self.final, expand=True, fillcolor="white")
        self.status.config(text="Reading the page…")
        self.tk.update_idletasks()
        self.found = suggestions(self.straight, self.page)
        self.render()
        self.status.config(text=f"{len(self.visible())} found by the scanner (dashed): click one to confirm or correct it, "
                                "or drag a box around one line.")

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

    def render(self):
        from PIL import ImageTk

        self.resize_job = None
        width, height = max(self.canvas.winfo_width(), 200), max(self.canvas.winfo_height(), 200)
        self.scale = min(width / self.straight.width, height / self.straight.height)
        shown = self.straight.resize((max(1, int(self.straight.width * self.scale)), max(1, int(self.straight.height * self.scale))))
        self.photo = ImageTk.PhotoImage(shown)
        self.canvas.delete("all")
        self.canvas.create_image(0, 0, image=self.photo, anchor="nw")
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

    def _draw_box(self, box, codes: list[str], caption: str, dash):
        color = COLORS.get(codes[0], "#7f7f7f")
        x0, y0, x1, y1 = (v * self.scale for v in self._px(box))
        self.canvas.create_rectangle(x0, y0, x1, y1, outline=color, width=2, dash=dash)
        self.canvas.create_text(x0, y0 - 2, text=caption, anchor="sw", fill=color)

    def _px(self, box) -> tuple[int, int, int, int]:
        x0, y0, x1, y1 = box
        w, h = self.straight.width, self.straight.height
        return int(x0 * w), int(y0 * h), int(x1 * w) + 1, int(y1 * h) + 1

    def _outline_selection(self):
        s = self.scale
        x0, y0, x1, y1 = self.box
        self.rect = self.canvas.create_rectangle(x0 * s, y0 * s, x1 * s, y1 * s, outline="red", width=3)

    def _hit(self, box, e, margin: int = 6) -> bool:
        x0, y0, x1, y1 = (v * self.scale for v in self._px(box))
        return x0 - margin <= e.x <= x1 + margin and y0 - 18 <= e.y <= y1 + margin

    def press(self, e):
        self.clear_box()
        for f in self.visible():
            if self._hit(f["box"], e):
                return self.select(f)
        for rec in self.saved_here():
            if self._hit(rec["box"], e):
                return self.edit(rec)
        self.drag_start = (e.x, e.y)

    def select(self, found: dict):
        self.selected, self.box = found, self._px(found["box"])
        self._fill([found["type"]], found["text"], self.hand_var.get())
        self._outline_selection()
        self.status.config(text=f"Scanner found {found['type']}. Change the types or text if wrong (None if not "
                                "sensitive), then Enter.")

    def edit(self, rec: dict):
        self.editing, self.box = rec, self._px(rec["box"])
        self._fill(label_types(rec), rec["text"], rec["handwritten"])
        self._outline_selection()
        self.status.config(text="Editing a saved label: change the types or text, then Enter. Or press Delete label.")

    def _fill(self, codes: list[str], text: str, handwritten: bool):
        for name, var in self.type_vars.items():
            var.set(LABEL_TYPES[name] in codes)
        self.text_var.set(text)
        self.hand_var.set(handwritten)
        self.entry.focus_set()

    def drag(self, e):
        if self.drag_start:
            if self.rect:
                self.canvas.delete(self.rect)
            self.rect = self.canvas.create_rectangle(*self.drag_start, e.x, e.y, outline="red", width=2)

    def release(self, e):
        if not (self.drag_start and self.straight):
            return
        (ax, ay), s = self.drag_start, self.scale
        x0, x1 = sorted((ax, e.x))
        y0, y1 = sorted((ay, e.y))
        self.box = (max(0, int(x0 / s)), max(0, int(y0 / s)),
                    min(self.straight.width, int(x1 / s)), min(self.straight.height, int(y1 / s)))
        self.drag_start = None
        self.entry.focus_set()

    def clear_box(self):
        if self.rect:
            self.canvas.delete(self.rect)
        self.box = self.drag_start = self.rect = self.selected = self.editing = None

    def save(self):
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
                self.store.save(self.file, self.page, self.straight, self.box, ticked, self.text_var.get(),
                                self.hand_var.get(), self.detected, self.final, suggested)
                self.counts[str(self.file)] = self.counts.get(str(self.file), 0) + 1
                corrected = suggested and [LABEL_TYPES[n] for n in ticked] != [suggested]
                message = "Saved your correction." if corrected else "Saved."
        except ValueError as e:
            self.status.config(text=str(e))
            return
        self._after_change(message)

    def delete(self):
        if not self.editing:
            self.status.config(text="Click a saved (solid) box first, then Delete label.")
            return
        self.store.delete(self.editing["id"])
        self.counts[str(self.file)] = max(0, self.counts.get(str(self.file), 0) - 1)
        self._after_change("Label deleted.")

    def _after_change(self, message: str):
        self.clear_box()
        self.text_var.set("")
        self.render()
        self.refresh_list()
        self.status.config(text=f"{message} {sum(self.counts.values())} labels in total; "
                                f"{len(self.visible())} suggestions left here.")

def run(root: Path | None, store_dir: Path = TRAINING_DIR) -> None:
    import tkinter as tk
    from tkinter import filedialog

    tk_root = tk.Tk()
    if root is None:
        tk_root.withdraw()
        chosen = filedialog.askdirectory(title="Choose the folder of scans to label", mustexist=True)
        if not chosen:
            tk_root.destroy()
            return
        root = Path(chosen)
        tk_root.deiconify()
    LabelWindow(tk_root, root, Store(store_dir))
    tk_root.lift()
    tk_root.attributes("-topmost", True)
    tk_root.after(500, lambda: tk_root.attributes("-topmost", False))
    tk_root.focus_force()
    tk_root.mainloop()
