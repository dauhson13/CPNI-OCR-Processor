import re
import zipfile
from pathlib import PurePath

import olefile

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
IMAGE_MAGIC = (b"II*\x00", b"MM\x00*", b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a")
HEIF_BRANDS = (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1", b"avif")
EMAIL_HEADER = re.compile(rb"^(Received|Return-Path|From|Delivered-To|Message-ID|MIME-Version|Date|To|Subject|X-[\w-]+):", re.I)


def sniff(head: bytes, name: str, f) -> str:
    ext = PurePath(name).suffix.lower()
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "ooxml" if _is_ooxml(f) else "zip"
    if head.startswith(OLE_MAGIC):
        return _ole_kind(f)
    if head.startswith(b"!BDN"):
        return "pst"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith(IMAGE_MAGIC) or (head[4:8] == b"ftyp" and head[8:12] in HEIF_BRANDS):
        return "image"
    if head.startswith(b"BM") and ext == ".bmp":
        return "image"
    if ext == ".eml" or EMAIL_HEADER.match(head):
        return "eml"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" not in head:
        return "text"
    return "unsupported"


def _is_ooxml(f) -> bool:
    f.seek(0)
    names = zipfile.ZipFile(f).namelist()
    return "[Content_Types].xml" in names and any(n.startswith(("word/", "xl/", "ppt/")) for n in names)


def _ole_kind(f) -> str:
    f.seek(0)
    with olefile.OleFileIO(f) as ole:
        names = {"/".join(e).lower() for e in ole.listdir(streams=True, storages=True)}
    if {"encryptioninfo", "encryptedpackage"} <= names:
        return "encrypted_ooxml"
    if names & {"workbook", "book"}:
        return "xls"
    if "worddocument" in names:
        return "doc"
    if "powerpoint document" in names:
        return "ppt"
    if any(n.startswith(("__substg1.0_", "__properties_version1.0")) for n in names):
        return "msg"
    return "unsupported"
