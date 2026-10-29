import pytest

from conftest import expect, found
from piiscan.extract import legacy
from piiscan.synth import docs
from piiscan.synth.values import INVALID_SSNS, account, digits, drivers_license, ssn


def statuses(records):
    return {(r["member"], r["status"]) for r in records}


def test_text_utf8_and_cp1252(scan_bytes, rng):
    s, a = ssn(rng), account(rng)
    for data in (docs.text([f"SSN {s}", f"acct {a}"]), docs.text(["Café", f"SSN {s}", f"acct {a}"], "cp1252")):
        recs = scan_bytes(data, "notes.txt")
        assert {expect("SSN", s), expect("CUSTOMER_ACCOUNT", a)} <= found(recs)
        assert recs[0]["status"] == "ok"


def test_utf16_text_and_line_locator(scan_bytes, rng):
    s = ssn(rng)
    recs = scan_bytes(docs.text(["header", "", f"SSN {s}"], "utf-16"), "export.txt")
    assert expect("SSN", s) in found(recs)
    assert recs[0]["findings"][0]["locator"] == "L3"


def test_invalid_ssns_are_not_reported(scan_bytes):
    recs = scan_bytes(docs.text(INVALID_SSNS), "bad.txt")
    assert not [f for f in recs[0]["findings"] if f["pii_type"] == "SSN"]


def test_pdf_text_layer_has_page_and_box(scan_bytes, rng):
    s = ssn(rng)
    recs = scan_bytes(docs.pdf_text(["Statement", f"SSN on file {s}"]), "s.pdf")
    f = next(f for f in recs[0]["findings"] if f["pii_type"] == "SSN")
    assert f["page"] == 1 and expect("SSN", s) in found(recs)
    x0, y0, x1, y1 = f["bbox"]
    assert 0 <= x0 < x1 <= 1 and 0 <= y0 < y1 <= 1 and y0 < 0.3


def test_pdf_form_field_values(scan_bytes, rng):
    s = ssn(rng)
    recs = scan_bytes(docs.pdf_form({"ssn": s}), "w9.pdf")
    assert expect("SSN", s) in found(recs)
    assert any(f["locator"] == "field:ssn" for f in recs[0]["findings"])


def test_pdf_scan_is_ocrd(scan_bytes, rng):
    s, a = ssn(rng), account(rng)
    lines = docs.filler_lines(rng, 5) + [f"Customer SSN: {s}", f"Account Number: {a}"] + docs.filler_lines(rng, 5)
    recs = scan_bytes(docs.pdf_scanned(lines, rotate=-4), "scan.pdf")
    assert recs[0]["status"] == "ok" and recs[0]["ocr_pages"] == 1 and recs[0]["rotated_pages"] == 1
    assert {expect("SSN", s), expect("CUSTOMER_ACCOUNT", a)} <= found(recs)
    f = next(f for f in recs[0]["findings"] if f["pii_type"] == "SSN")
    assert f["method"].endswith(("+ocr_printed", "+ocr_hand")) and f["bbox"] and "page turned" in f["locator"]
    assert len([f for f in recs[0]["findings"] if f["pii_type"] == "SSN"]) == 1


def test_pdf_encrypted(scan_bytes, rng):
    assert scan_bytes(docs.pdf_encrypted([f"SSN {ssn(rng)}"]), "x.pdf")[0]["status"] == "encrypted"


def test_pdf_attachment_is_scanned(scan_bytes, rng):
    s = ssn(rng)
    recs = scan_bytes(docs.pdf_with_attachment(["cover"], "att.txt", f"SSN {s}".encode()), "p.pdf")
    assert ("att.txt", "ok") in statuses(recs) and expect("SSN", s) in found(recs)


def test_docx_hidden_places(scan_bytes, rng):
    body, head, note, gone = ssn(rng), ssn(rng), ssn(rng), ssn(rng)
    a = account(rng)
    data = docs.docx([f"SSN {body}"], header=f"SSN {head}", comment=f"SSN {note}", deleted=f"SSN {gone}",
                     embedded=("Sheet.xlsx", docs.xlsx({"S": [["acct"], [a]]})))
    recs = scan_bytes(data, "letter.docx")
    assert {expect("SSN", v) for v in (body, head, note, gone)} <= found(recs)
    assert expect("CUSTOMER_ACCOUNT", a) in found(recs)
    assert ("Sheet.xlsx", "ok") in statuses(recs)


def test_xlsx_cells_hidden_sheet_and_numbers(scan_bytes, rng):
    s, a = ssn(rng), account(rng)
    bare = int(digits(ssn(rng)))
    data = docs.xlsx({"Visible": [["x"]], "Secret": [["ssn", "acct", "n"], [s, a, bare]]}, hidden={"Secret"})
    recs = scan_bytes(data, "a.xlsx")
    assert {expect("SSN", s), expect("CUSTOMER_ACCOUNT", a), expect("SSN", str(bare))} <= found(recs)
    assert {f["locator"] for f in recs[0]["findings"]} >= {"Secret!A2", "Secret!B2", "Secret!C2"}


def test_drivers_license_columns(scan_bytes, rng):
    d1, d2 = drivers_license(rng, "CA"), drivers_license(rng, "FL")
    recs = scan_bytes(docs.xlsx({"S": [["Customer report"], ["Name", "Driver License #"], ["Pat Doe", d1]]}), "a.xlsx")
    assert expect("DRIVERS_LICENSE", d1) in found(recs)
    assert [f["locator"] for f in recs[0]["findings"] if f["pii_type"] == "DRIVERS_LICENSE"] == ["S!B3"]
    s = ssn(rng)
    recs = scan_bytes(docs.text(["name,ssn,dl_number,city", f"Pat Doe,{s},{d2},Austin"]), "export.csv")
    assert {f["value_hmac"] for f in recs[0]["findings"] if f["pii_type"] == "DRIVERS_LICENSE"} == {
        expect("DRIVERS_LICENSE", d2)[1]}
    recs = scan_bytes(docs.xls([["name", "DL"], ["Pat", d1]]), "old.xls")
    assert expect("DRIVERS_LICENSE", d1) in found(recs)


def test_account_column_with_partial_values(scan_bytes, rng):
    a, b = account(rng), account(rng)
    recs = scan_bytes(docs.xlsx({"S": [["Acct #", "Balance"], [a[1:], "1234.56"], [b[-4:], "99"]]}), "a.xlsx")
    got = {(f["value_hmac"], f["method"]) for f in recs[0]["findings"] if f["pii_type"] == "CUSTOMER_ACCOUNT"}
    assert got == {(expect("CUSTOMER_ACCOUNT", a)[1], "column+missing_zero"),
                   (expect("CUSTOMER_ACCOUNT", b[-4:])[1], "column+partial")}


def test_pptx_slide_and_notes(scan_bytes, rng):
    s, n = ssn(rng), ssn(rng)
    recs = scan_bytes(docs.pptx(f"SSN {s}", notes=f"SSN {n}"), "deck.pptx")
    assert {expect("SSN", s), expect("SSN", n)} <= found(recs)


def test_xls(scan_bytes, rng):
    s, a = ssn(rng), account(rng)
    recs = scan_bytes(docs.xls([["ssn", "acct"], [s, a]]), "old.xls")
    assert {expect("SSN", s), expect("CUSTOMER_ACCOUNT", a)} <= found(recs)
    assert {f["locator"] for f in recs[0]["findings"]} == {"Accounts!A2", "Accounts!B2"}


def test_xls_many_workbooks(scan_bytes):
    import random

    for seed in range(40):
        r = random.Random(seed)
        s, a = ssn(r), account(r)
        recs = scan_bytes(docs.xls([["ssn", "account"], [s, a]]), "w.xls")
        assert recs[0]["status"] == "ok", seed
        assert {expect("SSN", s), expect("CUSTOMER_ACCOUNT", a)} <= found(recs), seed


def test_failed_encryption_check_does_not_hide_content(monkeypatch, scan_bytes):
    def boom(f):
        raise ValueError("parser crash")

    monkeypatch.setattr(legacy.msoffcrypto, "OfficeFile", boom)
    monkeypatch.setattr(legacy, "soffice", lambda: None)
    assert scan_bytes(docs.doc_encrypted_stub(), "x.doc")[0]["status"] == "unsupported"


def test_encrypted_office(scan_bytes, rng):
    assert scan_bytes(docs.encrypted_ooxml(docs.docx([f"SSN {ssn(rng)}"])), "x.docx")[0]["status"] == "encrypted"
    assert scan_bytes(docs.doc_encrypted_stub(), "x.doc")[0]["status"] == "encrypted"


@pytest.mark.skipif(not legacy.soffice(), reason="LibreOffice not installed")
def test_doc_via_libreoffice(scan_bytes, rng, tmp_path):
    import subprocess

    s = ssn(rng)
    (tmp_path / "in.docx").write_bytes(docs.docx([f"SSN {s}"]))
    subprocess.run([legacy.soffice(), "--headless", "--convert-to", "doc", "--outdir", str(tmp_path),
                    str(tmp_path / "in.docx")], check=True, capture_output=True, timeout=120)
    recs = scan_bytes((tmp_path / "in.doc").read_bytes(), "in.doc")
    assert recs[0]["type"] == "doc" and expect("SSN", s) in found(recs)


def test_rtf(scan_bytes, rng):
    s = ssn(rng)
    assert expect("SSN", s) in found(scan_bytes(docs.rtf(f"Memo\nSSN {s}"), "m.rtf"))


def test_eml_body_html_and_attachment(scan_bytes, rng):
    body, html, att = account(rng), ssn(rng), ssn(rng)
    data = docs.eml("Update", f"Account {body}", [("form.docx", docs.docx([f"SSN {att}"]))], html=f"<p>SSN {html}</p>")
    recs = scan_bytes(data, "m.eml")
    assert {expect("CUSTOMER_ACCOUNT", body), expect("SSN", html), expect("SSN", att)} <= found(recs)
    assert ("form.docx", "ok") in statuses(recs)


def test_msg_with_attachment(scan_bytes, rng):
    a, s = account(rng), ssn(rng)
    recs = scan_bytes(docs.msg("Autopay", f"Account {a}", [("auth.txt", f"SSN {s}".encode())]), "m.msg")
    assert recs[0]["type"] == "msg"
    assert {expect("CUSTOMER_ACCOUNT", a), expect("SSN", s)} <= found(recs)
    assert ("auth.txt", "ok") in statuses(recs)


def test_zip_nested_encrypted_member_and_depth_limit(scan_bytes, rng):
    s, a = ssn(rng), account(rng)
    data = docs.zip_({"a.txt": f"SSN {s}".encode(), "inner.zip": docs.zip_({"b.txt": f"acct {a}".encode()}),
                      "secret.txt": b"locked"}, encrypted={"secret.txt"})
    recs = scan_bytes(data, "batch.zip")
    assert {expect("SSN", s), expect("CUSTOMER_ACCOUNT", a)} <= found(recs)
    assert {("inner.zip!/b.txt", "ok"), ("secret.txt", "encrypted")} <= statuses(recs)

    deep = f"SSN {ssn(rng)}".encode()
    for i in range(7):
        deep = docs.zip_({f"level{i}.zip" if i else "x.txt": deep})
    recs = scan_bytes(deep, "deep.zip")
    assert any(r["status"] == "too_large" for r in recs) and not found(recs)


def test_corrupt_and_unsupported(scan_bytes):
    assert scan_bytes(docs.pdf_text(["x" * 50])[:300], "cut.pdf")[0]["status"] == "corrupt"
    assert scan_bytes(docs.docx(["hello"])[:400], "cut.docx")[0]["status"] == "corrupt"
    rec = scan_bytes(bytes(range(256)) * 4, "tool.bin")[0]
    assert rec["status"] == "unsupported"
    assert all(r["error"] is None or "Error at" in r["error"] or "Exception at" in r["error"]
               for r in scan_bytes(docs.pdf_text(["x" * 50])[:300], "cut.pdf"))


def test_images_are_ocrd(scan_bytes):
    rec = scan_bytes(docs.tiff(3), "fax.tif")[0]
    assert (rec["status"], rec["ocr_pages"], rec["pages"]) == ("ok", 3, 3)
    assert scan_bytes(docs.heic(), "photo.heic")[0]["ocr_pages"] == 1


def test_pst_walk(monkeypatch, scan_bytes, rng):
    from types import SimpleNamespace as NS

    from piiscan.extract import pst

    s, a = ssn(rng), account(rng)
    att = NS(long_filename="auth.txt", size=len(f"SSN {s}"), read_buffer=lambda n: f"SSN {s}".encode())
    msg = NS(subject="Autopay", sender_name="Billing", transport_headers=None, plain_text_body=f"Acct {a}".encode(),
             html_body=None, number_of_attachments=1, get_attachment=lambda k: att)
    inbox = NS(name="Inbox", number_of_sub_messages=1, get_sub_message=lambda i: msg, number_of_sub_folders=0)
    root = NS(name="", number_of_sub_messages=0, number_of_sub_folders=1, get_sub_folder=lambda j: inbox)
    fake = NS(open_file_object=lambda f: None, get_root_folder=lambda: root, close=lambda: None)
    monkeypatch.setattr(pst.pypff, "file", lambda: fake)
    recs = scan_bytes(b"!BDN" + b"\0" * 100, "mail.pst")
    assert {expect("CUSTOMER_ACCOUNT", a), expect("SSN", s)} <= found(recs)
    assert any(f["locator"] == "/Inbox#0:body" for f in recs[0]["findings"])
