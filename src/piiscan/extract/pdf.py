import pypdfium2 as pdfium
from defusedxml import ElementTree as ET
from pypdf import PdfReader

from ..model import Child, Encrypted, Image, Span

MIN_TEXT_CHARS = 20
RENDER_SCALE = 300 / 72


def extract(f, name):
    try:
        pdf = pdfium.PdfDocument(f)
    except pdfium.PdfiumError as e:
        if e.err_code == pdfium.raw.FPDF_ERR_PASSWORD:
            raise Encrypted from None
        raise
    try:
        for i in range(len(pdf)):
            page = pdf[i]
            textpage = page.get_textpage()
            text = textpage.get_text_range()
            if len("".join(text.split())) >= MIN_TEXT_CHARS:
                yield Span(text, page=i + 1, where=_boxes(textpage, *page.get_size()))
            else:
                yield Image(page=i + 1, locator=None, load=lambda page=page: page.render(scale=RENDER_SCALE).to_pil())
        for j in range(pdf.count_attachments()):
            att = pdf.get_attachment(j)
            yield Child(att.get_name() or f"attachment{j}", bytes(att.get_data()))
    finally:
        pdf.close()
    f.seek(0)
    yield from _forms(f)


def _boxes(textpage, width, height):
    def where(start, end):
        boxes = [textpage.get_charbox(k) for k in range(start, end)]
        left, bottom = min(b[0] for b in boxes), min(b[1] for b in boxes)
        right, top = max(b[2] for b in boxes), max(b[3] for b in boxes)
        return None, (left / width, 1 - top / height, right / width, 1 - bottom / height)

    return where


def _forms(f):
    try:
        reader = PdfReader(f)
        if reader.is_encrypted:
            reader.decrypt("")
        for name, field in (reader.get_fields() or {}).items():
            value = field.get("/V")
            if isinstance(value, str) and value.strip():
                yield Span(f"{name}: {value}", locator=f"field:{name[:100]}")
        for i, page in enumerate(reader.pages):
            for annot in page.get("/Annots") or []:
                contents = annot.get_object().get("/Contents")
                if isinstance(contents, str) and contents.strip():
                    yield Span(contents, page=i + 1, locator="annotation")
        datasets = (reader.xfa or {}).get("datasets")
        if datasets:
            root = ET.fromstring(datasets)
            text = "\n".join(e.text.strip() for e in root.iter() if e.text and e.text.strip())
            yield Span(text, locator="xfa")
    except Exception:
        return
