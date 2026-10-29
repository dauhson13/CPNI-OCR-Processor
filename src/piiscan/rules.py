import getpass
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import db
from .detect import _nanp, address_key, custom_entry, detect, value_hmac

PATH = db.PROJECT_DIR / "data" / "rules.json"
NONE = "None (no sensitive data)"
GROUPS = ["Identification", "Bank info", "CPNI", "Other"]
ORDER = ["Identification", "SSN", *GROUPS[1:], NONE]
LABEL_TYPES = {
    "Identification: Driver's license #": "DRIVERS_LICENSE",
    "Identification: State ID #": "STATE_ID",
    "Identification: Passport #": "PASSPORT",
    "Identification: ITIN (tax ID)": "ITIN",
    "Identification: Date of birth": "DATE_OF_BIRTH",
    "SSN": "SSN",
    "Bank info: Bank account #": "BANK_ACCOUNT",
    "Bank info: Routing #": "ROUTING_NUMBER",
    "Bank info: Card #": "CARD_NUMBER",
    "Bank info: Card expiration / CVV": "CARD_SECURITY",
    "CPNI: Customer account #": "CUSTOMER_ACCOUNT",
    "CPNI: Phone #": "PHONE_NUMBER",
    "CPNI: Call detail": "CALL_DETAIL",
    "CPNI: Usage (minutes / data)": "USAGE",
    "CPNI: Services / plan / features": "SERVICE_PLAN",
    "CPNI: Billing amount": "BILLING_AMOUNT",
    "CPNI: Payment history": "PAYMENT_HISTORY",
    "CPNI: Service / E911 address": "SERVICE_ADDRESS",
    "CPNI: IP address": "IP_ADDRESS",
    "CPNI: MAC address": "MAC_ADDRESS",
    "CPNI: Equipment serial / device ID": "EQUIPMENT_ID",
    "CPNI: Circuit ID": "CIRCUIT_ID",
    "CPNI: Account password / PIN": "CREDENTIAL",
    "CPNI: Security answer": "SECURITY_ANSWER",
    "Other: Name": "PERSON_NAME",
    "Other: Address": "ADDRESS",
    "Other: Email": "EMAIL",
    NONE: "NONE",
}
COLORS = {
    "SSN": "#d62728", "ITIN": "#8b0000", "DRIVERS_LICENSE": "#1f77b4", "STATE_ID": "#00a0b0", "PASSPORT": "#6a3d9a",
    "DATE_OF_BIRTH": "#ff1493", "BANK_ACCOUNT": "#2ca02c", "ROUTING_NUMBER": "#006400", "CARD_NUMBER": "#ff7f0e",
    "CARD_SECURITY": "#ff4500", "CUSTOMER_ACCOUNT": "#e6007e", "PHONE_NUMBER": "#8c564b", "CALL_DETAIL": "#b8860b",
    "USAGE": "#9acd32", "SERVICE_PLAN": "#808000", "BILLING_AMOUNT": "#4682b4", "PAYMENT_HISTORY": "#1e90ff",
    "SERVICE_ADDRESS": "#5f9ea0", "IP_ADDRESS": "#4b0082", "MAC_ADDRESS": "#2f4f4f", "EQUIPMENT_ID": "#bc8f8f",
    "CIRCUIT_ID": "#483d8b", "CREDENTIAL": "#000000", "SECURITY_ANSWER": "#bdb76b", "PERSON_NAME": "#9932cc",
    "ADDRESS": "#008b8b", "EMAIL": "#556b2f", "NONE": "#7f7f7f",
}
CUSTOM_COLORS = ["#e377c2", "#17becf", "#bcbd22", "#9467bd", "#ff9896", "#98df8a", "#c49c94", "#aec7e8", "#ffbb78",
                 "#f7b6d2"]
SAME_VALUE = {"ADDRESS": "SERVICE_ADDRESS", "SERVICE_ADDRESS": "ADDRESS"}


class Rules:

    def __init__(self, path: Path | None = None, data: dict | None = None):
        self.path = path
        if data is None:
            data = json.loads(path.read_text(encoding="utf-8")) if path and path.exists() else {}
        self.types: list[dict] = data.get("types", [])
        self.bypass: list[dict] = data.get("bypass", [])
        self._compile()

    def data(self) -> dict:
        return {"types": self.types, "bypass": self.bypass}

    def names(self) -> dict[str, str]:
        everything = LABEL_TYPES | {f"{t['group']}: {t['name']}": t["code"] for t in self.types}
        place = {group: i for i, group in enumerate(ORDER)}
        return dict(sorted(everything.items(), key=lambda kv: place.get(kv[0].split(":")[0], place["Other"])))

    def codes(self) -> list[str]:
        return sorted(set(self.names().values()) - {"NONE"})

    def color(self, code: str) -> str:
        custom = [t["code"] for t in self.types]
        if code in COLORS:
            return COLORS[code]
        return CUSTOM_COLORS[custom.index(code) % len(CUSTOM_COLORS)] if code in custom else COLORS["NONE"]

    def add_type(self, group: str, name: str, words: str = "") -> dict:
        name = " ".join(name.split())
        if group not in GROUPS:
            raise ValueError("pick a group for the new type")
        if not name:
            raise ValueError("give the new type a name")
        code = re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")
        if not code or code in self.names().values() or f"{group}: {name}" in self.names():
            raise ValueError("that type is already in the list")
        phrases = [" ".join(w.lower().split()) for w in (words or name).split(",") if re.search(r"[A-Za-z0-9]", w)]
        if not phrases:
            raise ValueError("give the words printed next to it on forms")
        rec = {"group": group, "name": name, "code": code, "words": phrases, "added_by": getpass.getuser(),
               "added_at": _now()}
        self.types.append(rec)
        self._save()
        return rec

    def remove_type(self, code: str) -> None:
        self.types = [t for t in self.types if t["code"] != code]
        self._save()

    def add_bypass(self, types: list[str], value: str, also=()) -> dict:
        types = [t for t in types if t != "NONE"]
        value = " ".join(value.split())
        if not types:
            raise ValueError("tick what kind of company info it is (Phone #, Address, ...)")
        if not value:
            raise ValueError("type the company info exactly as printed")
        rec = {"types": types, "value": value, "also": [list(k) for k in also], "added_by": getpass.getuser(),
               "added_at": _now()}
        self.bypass.append(rec)
        self._save()
        return rec

    def remove_bypass(self, index: int) -> None:
        del self.bypass[index]
        self._save()

    def skips(self, pii_type: str, normalized: str) -> bool:
        return (pii_type, normalized) in self.skip

    def hmacs(self, key: bytes) -> set[str]:
        return {value_hmac(key, t, n) for t, n in self.skip}

    def _compile(self) -> None:
        self.entries = [custom_entry(t["code"], t["words"]) for t in self.types]
        self.skip = {k for b in self.bypass for k in bypass_keys(b["types"], b["value"], b.get("also", []))}

    def _save(self) -> None:
        self._compile()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(self.data(), indent=2), encoding="utf-8")
            tmp.replace(self.path)


def bypass_keys(types: list[str], value: str, also=()) -> set[tuple[str, str]]:
    wanted = set(types) | {SAME_VALUE[t] for t in types if t in SAME_VALUE}
    digits = re.sub(r"\D", "", value)
    forms = {value, " ".join(value.split()).lower(), re.sub(r"[\s-]", "", value).upper(), digits, address_key(value),
             _nanp(digits) if digits else None, "0" + digits if len(digits) == 10 else None}
    keys = {(t, f) for t in wanted for f in forms if f}
    keys |= {(t, n) for t, _, _, n, _, _ in detect(value) if t in wanted}
    return keys | {tuple(k) for k in also}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
