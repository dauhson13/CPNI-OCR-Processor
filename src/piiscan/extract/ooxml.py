import bisect
import io
import posixpath
import zipfile

from defusedxml import ElementTree as ET

from ..model import HEADER_ROWS, Child, Image, Span, TooLarge

MAX_PART = 256 << 20
TEXT_TAGS = {"t", "delText"}
BREAK_TAGS = {"p", "si", "comment"}


def extract(f, name):
    with zipfile.ZipFile(f) as z:
        names = z.namelist()
        is_xlsx = "xl/workbook.xml" in names
        if is_xlsx:
            yield from _xlsx(z, names)
        for n in names:
            low = n.lower()
            if "/media/" in low:
                yield Image(page=None, locator=n, load=lambda n=n: _pil(_read(z, n)))
            elif "/embeddings/" in low:
                yield Child(posixpath.basename(n), _read(z, n))
            elif not low.endswith(".xml") or low.startswith("docprops/") or low == "[content_types].xml":
                continue
            elif is_xlsx and (low.startswith("xl/worksheets/") or low == "xl/sharedstrings.xml"):
                continue
            else:
                text = _all_text(_read(z, n)) if low.startswith("customxml/") else _runs_text(_read(z, n))
                if text.strip():
                    yield Span(text, locator=n)


def _read(z, n):
    info = z.getinfo(n)
    if info.file_size > MAX_PART:
        raise TooLarge
    with z.open(info) as m:
        data = m.read(MAX_PART + 1)
    if len(data) > MAX_PART:
        raise TooLarge
    return data


def _pil(data):
    from PIL import Image as PILImage

    return PILImage.open(io.BytesIO(data))


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _runs_text(data):
    lines, buf = [], []
    for event, el in ET.iterparse(io.BytesIO(data), events=("end",)):
        tag = _local(el.tag)
        if tag in TEXT_TAGS and el.text:
            buf.append(el.text)
        elif tag == "tab":
            buf.append("\t")
        elif tag in BREAK_TAGS and buf:
            lines.append("".join(buf))
            buf.clear()
    if buf:
        lines.append("".join(buf))
    return "\n".join(lines)


def _all_text(data):
    root = ET.fromstring(data)
    return "\n".join(e.text.strip() for e in root.iter() if e.text and e.text.strip())


def _xlsx(z, names):
    shared = []
    if "xl/sharedStrings.xml" in names:
        root = ET.fromstring(_read(z, "xl/sharedStrings.xml"))
        shared = ["".join(t.text or "" for t in si.iter() if _local(t.tag) == "t") for si in root]
    for part, sheet in _sheets(z, names):
        rows, cells = [], []
        for event, el in ET.iterparse(io.BytesIO(_read(z, part)), events=("end",)):
            tag = _local(el.tag)
            if tag == "c":
                value = _cell_value(el, shared)
                if value:
                    cells.append((el.get("r") or "?", value))
                el.clear()
            elif tag == "row":
                if cells:
                    rows.append(cells)
                    cells = []
                el.clear()
        if rows:
            yield table_span(sheet, rows)


def _cell_value(c, shared):
    kind = c.get("t")
    if kind == "inlineStr":
        return "".join(t.text or "" for t in c.iter() if _local(t.tag) == "t")
    v = next((e.text for e in c if _local(e.tag) == "v"), None)
    if v is None:
        return ""
    if kind == "s":
        return shared[int(v)] if int(v) < len(shared) else ""
    if kind in (None, "n"):
        return _number(v)
    return v


def _number(v):
    try:
        x = float(v)
    except ValueError:
        return v
    return str(int(x)) if x.is_integer() and ("E" in v or "e" in v or v.endswith(".0")) else v


def table_span(sheet: str, rows: list[list[tuple[str, str]]]) -> Span:
    lines, starts, refs, heads, offset = [], [], [], {}, 0
    for i, cells in enumerate(rows):
        for ref, value in cells:
            starts.append(offset)
            refs.append(ref)
            offset += len(value) + 1
            if i < HEADER_ROWS:
                heads.setdefault(ref.rstrip("0123456789"), []).append(value)
        lines.append("\t".join(v for _, v in cells))

    def ref_at(start):
        return refs[bisect.bisect_right(starts, start) - 1]

    return Span("\n".join(lines), locator=sheet, where=lambda start, end: (f"{sheet}!{ref_at(start)}", None),
                header=lambda start: "\n".join(heads.get(ref_at(start).rstrip("0123456789"), ())))


def _sheets(z, names):
    parts = sorted(n for n in names if n.startswith("xl/worksheets/") and n.endswith(".xml"))
    try:
        rels = ET.fromstring(_read(z, "xl/_rels/workbook.xml.rels"))
        target = {r.get("Id"): r.get("Target") for r in rels}
        wb = ET.fromstring(_read(z, "xl/workbook.xml"))
        out = []
        for s in wb.iter():
            if _local(s.tag) != "sheet":
                continue
            rid = next(v for k, v in s.attrib.items() if _local(k) == "id")
            t = target[rid]
            part = t.lstrip("/") if t.startswith("/") else posixpath.normpath(posixpath.join("xl", t))
            if part in names:
                out.append((part, s.get("name")))
        return out or [(p, posixpath.basename(p)) for p in parts]
    except (KeyError, StopIteration, ET.ParseError):
        return [(p, posixpath.basename(p)) for p in parts]
