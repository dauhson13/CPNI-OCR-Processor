import io
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import msoffcrypto
import xlrd

from ..model import Encrypted, Unsupported
from . import ooxml

CONVERT_TIMEOUT = 300


def _check_encrypted(f):
    try:
        encrypted = msoffcrypto.OfficeFile(f).is_encrypted()
    except Exception:
        encrypted = False
    f.seek(0)
    if encrypted:
        raise Encrypted


def extract_xls(f, name):
    try:
        book = xlrd.open_workbook(file_contents=f.read(), on_demand=True)
    except xlrd.XLRDError as e:
        if "encrypt" in str(e).lower():
            raise Encrypted from None
        raise
    for sheet in book.sheets():
        rows = []
        for r in range(sheet.nrows):
            cells = []
            for c in range(sheet.ncols):
                cell = sheet.cell(r, c)
                value = cell.value
                if cell.ctype == xlrd.XL_CELL_NUMBER and float(value).is_integer():
                    value = int(value)
                value = str(value) if value not in ("", None) else ""
                if value:
                    cells.append((xlrd.formula.cellname(r, c), value))
            if cells:
                rows.append(cells)
        if rows:
            yield ooxml.table_span(sheet.name, rows)


def extract_doc(f, name):
    _check_encrypted(f)
    yield from ooxml.extract(io.BytesIO(_convert(f, "doc", "docx")), name)


def extract_ppt(f, name):
    _check_encrypted(f)
    yield from ooxml.extract(io.BytesIO(_convert(f, "ppt", "pptx")), name)


def soffice() -> str | None:
    candidates = [
        shutil.which("soffice"),
        shutil.which("libreoffice"),
        Path("/Applications/LibreOffice.app/Contents/MacOS/soffice"),
        Path(os.environ.get("ProgramFiles", "")) / "LibreOffice" / "program" / "soffice.exe",
    ]
    return next((str(c) for c in candidates if c and Path(c).is_file()), None)


def _convert(f, src_ext, dst_ext) -> bytes:
    exe = soffice()
    if not exe:
        raise Unsupported
    with tempfile.TemporaryDirectory(prefix="piiscan-") as tmp:
        tmp = Path(tmp)
        src = tmp / f"in.{src_ext}"
        src.write_bytes(f.read())
        subprocess.run(
            [exe, f"-env:UserInstallation={(tmp / 'profile').as_uri()}", "--headless", "--norestore",
             "--convert-to", dst_ext, "--outdir", str(tmp), str(src)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=CONVERT_TIMEOUT, check=False,
        )
        out = tmp / f"in.{dst_ext}"
        if not out.is_file():
            raise ValueError("conversion failed")
        return out.read_bytes()
