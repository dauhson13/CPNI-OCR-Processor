import getpass
from pathlib import Path

from . import db
from .labeling import LABEL_TYPES

TYPES = sorted(set(LABEL_TYPES.values()) - {"NONE"})
QUERY = """
    SELECT fi.finding_id, f.path, fi.page, fi.locator, fi.pii_type, fi.confidence, fi.method
    FROM findings fi JOIN files f ON f.file_id = fi.file_id
    WHERE fi.run_id = f.last_scanned_run AND f.missing_since IS NULL AND {where}
    ORDER BY fi.confidence"""


def review(db_path: Path, ask=input, say=print, everything: bool = False, pii_type: str | None = None) -> dict[str, int]:
    where, args = ("fi.review_status != 'rejected'", []) if everything or pii_type else ("fi.review_status = 'needs_review'", [])
    if pii_type:
        where, args = where + " AND fi.pii_type = ?", [pii_type]
    con = db.connect(db_path)
    done = {"confirmed": 0, "rejected": 0, "corrected": 0}
    try:
        queue = con.execute(QUERY.format(where=where), args).fetchall()
        if not queue:
            say("Nothing to review.")
        for i, (finding_id, path, page, locator, found_type, conf, method) in enumerate(queue, 1):
            say(f"\n[{i}/{len(queue)}] {found_type}  confidence {conf:.2f}  ({method})\n  {path}\n  page {page or '-'}, {locator}")
            answer = ask("  [c]onfirm  [r]eject  [t] change type  [s]kip  [q]uit > ").strip().lower()[:1]
            if answer == "q":
                break
            if answer == "t":
                new_type = _pick_type(ask, say)
                if new_type and new_type != found_type:
                    _decide(con, finding_id, "corrected", pii_type=new_type)
                    db.audit(con, "review_corrected", detail={"finding_id": finding_id, "from": found_type, "to": new_type})
                    done["corrected"] += 1
            elif answer in ("c", "r"):
                status = "confirmed" if answer == "c" else "rejected"
                _decide(con, finding_id, status)
                db.audit(con, f"review_{status}", detail={"finding_id": finding_id})
                done[status] += 1
    finally:
        con.close()
    return done


def _pick_type(ask, say) -> str | None:
    say("  " + "   ".join(f"{n}) {t}" for n, t in enumerate(TYPES, 1)))
    choice = ask("  new type number > ").strip()
    return TYPES[int(choice) - 1] if choice.isdigit() and 1 <= int(choice) <= len(TYPES) else None


def _decide(con, finding_id: int, status: str, pii_type: str | None = None) -> None:
    with con:
        con.execute("UPDATE findings SET review_status = ?, pii_type = COALESCE(?, pii_type), reviewed_by = ?,"
                    " reviewed_at = ? WHERE finding_id = ?", (status, pii_type, getpass.getuser(), db.now(), finding_id))
