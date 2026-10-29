from pathlib import PurePath

from striprtf.striprtf import rtf_to_text

from ..model import HEADER_ROWS, Span, TooLarge

CHUNK = 1 << 20
MAX_UTF16 = 256 << 20
DELIMITERS = {".csv": ",", ".tsv": "\t"}


def extract_text(f, name):
    delim = DELIMITERS.get(PurePath(name).suffix.lower())
    heads = None
    head = f.read(2)
    f.seek(0)
    if head in (b"\xff\xfe", b"\xfe\xff"):
        data = f.read(MAX_UTF16 + 1)
        if len(data) > MAX_UTF16:
            raise TooLarge
        text = data.decode("utf-16", errors="replace")
        yield Span(text, header=_csv_header(text, delim, _csv_heads(text, delim)) if delim else None)
        return
    encoding, line = None, 1
    while block := f.read(CHUNK):
        block += f.readline()
        if encoding is None:
            try:
                block.decode("utf-8-sig")
                encoding = "utf-8-sig"
            except UnicodeDecodeError:
                encoding = "cp1252"
        text = block.decode(encoding, errors="replace")
        encoding = "utf-8" if encoding == "utf-8-sig" else encoding
        if delim and heads is None:
            heads = _csv_heads(text, delim)
        yield Span(text, line0=line, header=_csv_header(text, delim, heads) if delim else None)
        line += text.count("\n")


def _csv_heads(text: str, delim: str) -> dict[int, list[str]]:
    heads: dict[int, list[str]] = {}
    for row in text.split("\n", HEADER_ROWS)[:HEADER_ROWS]:
        for i, value in enumerate(row.split(delim)):
            heads.setdefault(i, []).append(value.strip().strip('"'))
    return heads


def _csv_header(text: str, delim: str, heads: dict[int, list[str]]):
    def header(start):
        return "\n".join(heads.get(text.count(delim, text.rfind("\n", 0, start) + 1, start), ()))

    return header


def extract_rtf(f, name):
    yield Span(rtf_to_text(f.read().decode("latin-1"), errors="ignore"))
