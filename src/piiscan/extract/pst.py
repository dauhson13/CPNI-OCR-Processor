import pypff

from ..model import Child, Span
from .mail import html_text


def extract(f, name):
    store = pypff.file()
    store.open_file_object(f)
    try:
        yield from _folder(store.get_root_folder(), "")
    finally:
        store.close()


def _folder(folder, path):
    for i in range(folder.number_of_sub_messages):
        yield from _message(folder.get_sub_message(i), f"{path or '/'}#{i}")
    for j in range(folder.number_of_sub_folders):
        sub = folder.get_sub_folder(j)
        yield from _folder(sub, f"{path}/{sub.name or j}")


def _message(m, loc):
    head = "\n".join(v for v in (m.subject, m.sender_name, m.transport_headers) if v)
    if head:
        yield Span(head, locator=f"{loc}:headers")
    if m.plain_text_body:
        yield Span(m.plain_text_body.decode("utf-8", errors="replace"), locator=f"{loc}:body")
    elif m.html_body:
        yield Span(html_text(m.html_body.decode("utf-8", errors="replace")), locator=f"{loc}:body.html")
    for k in range(m.number_of_attachments):
        a = m.get_attachment(k)
        size = a.size
        yield Child(a.long_filename or f"attachment{k}", a.read_buffer(size) if size else b"")
