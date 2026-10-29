import email
import email.policy
from html.parser import HTMLParser

import extract_msg

from ..model import Child, Span

HEADERS = ("from", "to", "cc", "bcc", "reply-to", "subject")


def extract_eml(f, name):
    msg = email.message_from_binary_file(f, policy=email.policy.default)
    head = "\n".join(f"{k}: {v}" for k, v in msg.items() if k.lower() in HEADERS)
    if head:
        yield Span(head, locator="headers")
    for i, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment" or not ctype.startswith("text/"):
            payload = part.get_payload(decode=True)
            if payload:
                yield Child(filename or f"part{i}.{part.get_content_subtype()}", payload)
        elif ctype == "text/html":
            yield Span(html_text(_text(part)), locator="body.html")
        else:
            yield Span(_text(part), locator="body")


def _text(part):
    try:
        return part.get_content()
    except (LookupError, UnicodeError):
        return (part.get_payload(decode=True) or b"").decode("latin-1")


def extract_msg_file(f, name):
    msg = extract_msg.openMsg(f.read())
    try:
        head = "\n".join(f"{k}: {v}" for k, v in (("From", msg.sender), ("To", msg.to), ("Cc", msg.cc), ("Subject", msg.subject)) if v)
        if head:
            yield Span(head, locator="headers")
        if msg.body:
            yield Span(msg.body, locator="body")
        elif msg.htmlBody:
            yield Span(html_text(msg.htmlBody.decode("utf-8", errors="replace")), locator="body.html")
        for i, att in enumerate(msg.attachments):
            data = att.data
            label = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or f"attachment{i}"
            if isinstance(data, bytes):
                yield Child(label, data)
            elif hasattr(data, "exportBytes"):
                yield Child(f"{label}.msg", data.exportBytes())
    finally:
        msg.close()


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.out, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def html_text(html: str) -> str:
    p = _HTMLText()
    p.feed(html)
    return "\n".join(s.strip() for s in p.out if s.strip())
