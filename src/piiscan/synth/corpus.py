import random
from pathlib import Path

from . import docs
from .values import account, digits, drivers_license, ssn


def build(root: Path, rng: random.Random) -> dict[str, dict[str, set[str]]]:
    truth: dict[str, dict[str, set[str]]] = {}

    def put(rel: str, data: bytes, ssns=(), accounts=(), dls=()):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if ssns or accounts or dls:
            truth[rel] = {"SSN": {digits(s) for s in ssns}, "CUSTOMER_ACCOUNT": set(accounts), "DRIVERS_LICENSE": set(dls)}

    s, a, d = ssn(rng), account(rng), drivers_license(rng, "CA")
    put("Billing/notes.txt", docs.text([f"Customer SSN {s}", f"Acct {a}", f"Driver's License: {d}"]), [s], [a], [d])
    s, a, d = ssn(rng), account(rng), drivers_license(rng, "FL")
    put("Billing/export.csv", docs.text(["name,ssn,account,dl_number", f"Pat Doe,{s},{a},{d}"]), [s], [a], [d])
    s, a = ssn(rng), account(rng)
    put("Billing/statement.pdf", docs.pdf_text([f"Account number {a}", f"SSN on file {s}"]), [s], [a])
    s, d = ssn(rng), drivers_license(rng, "CA")
    put("HR/w9_form.pdf", docs.pdf_form({"ssn": s, "name": "Pat Doe", "dl_number": d}), [s], dls=[d])
    s, a = ssn(rng), account(rng)
    put("HR/letter.docx", docs.docx(["Dear customer,"], header=f"Ref {a}", comment=f"SSN {s}"), [s], [a])
    s, a, d = ssn(rng), account(rng), drivers_license(rng, "FL")
    put("Billing/accounts.xlsx", docs.xlsx({"Visible": [["note"], ["none"]],
                                            "Hidden": [["Customer export"], ["ssn", "acct", "Drivers License"], [s, a, d]]},
                                           hidden={"Hidden"}), [s], [a], [d])
    s, a = ssn(rng), account(rng)
    put("Sales/deck.pptx", docs.pptx("Q3 review", notes=f"Call back re SSN {s}. Account No: {a[1:]}"), [s], [a])
    s, a = ssn(rng), account(rng)
    put("Archive/old.xls", docs.xls([["ssn", "account"], [s, a]]), [s], [a])
    s, a = ssn(rng), account(rng)
    put("Archive/memo.rtf", docs.rtf(f"Memo\nSSN {s}\nAcct # (last 4): {a[-4:]}"), [s], [a[-4:]])
    s, a = ssn(rng), account(rng)
    put("Mail/request.eml", docs.eml("Account update", f"Account {a}", [("form.txt", f"SSN {s}".encode())]), [s], [a])
    s, a = ssn(rng), account(rng)
    put("Mail/saved.msg", docs.msg("Autopay", f"Account {a}", [("auth.txt", f"SSN {s}".encode())]), [s], [a])
    s, a = ssn(rng), account(rng)
    put("Archive/batch.zip", docs.zip_({"inner/a.txt": f"SSN {s}".encode(),
                                        "nested.zip": docs.zip_({"b.txt": f"Acct {a}".encode()})}), [s], [a])
    s, a = ssn(rng), account(rng)
    put("Scans/scan.pdf", docs.pdf_scanned(docs.filler_lines(rng, 8) + [f"Customer SSN: {s}", f"Account Number: {a}"]
                                           + docs.filler_lines(rng, 8), rotate=2), [s], [a])
    d = drivers_license(rng, "CA")
    put("Scans/sideways.pdf", docs.pdf_scanned(docs.filler_lines(rng, 8) + [f"Driver's License: {d}"]
                                               + docs.filler_lines(rng, 8), rotate=80), dls=[d])
    s = ssn(rng)
    put("Scans/fax.tif", docs.tiff(images=[docs.page_image(docs.filler_lines(rng)),
                                           docs.page_image(docs.filler_lines(rng, 8) + [f"SSN: {s}"]
                                                           + docs.filler_lines(rng, 8), rotate=180)]), [s])
    put("HR/locked.pdf", docs.pdf_encrypted([f"SSN {ssn(rng)}"]))
    put("HR/locked.docx", docs.encrypted_ooxml(docs.docx([f"SSN {ssn(rng)}"])))
    put("Archive/broken.pdf", docs.pdf_text(["x" * 40])[:200])
    put("Archive/tool.bin", bytes(range(256)) * 4)
    return truth
