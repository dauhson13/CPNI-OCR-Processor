from . import archive, image, legacy, mail, ooxml, pdf, pst, text

EXTRACTORS = {
    "pdf": pdf.extract,
    "ooxml": ooxml.extract,
    "xls": legacy.extract_xls,
    "doc": legacy.extract_doc,
    "ppt": legacy.extract_ppt,
    "text": text.extract_text,
    "rtf": text.extract_rtf,
    "eml": mail.extract_eml,
    "msg": mail.extract_msg_file,
    "pst": pst.extract,
    "zip": archive.extract,
    "image": image.extract,
}
