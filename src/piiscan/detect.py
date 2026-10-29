import hashlib
import hmac
import re
from collections.abc import Callable, Iterator
from datetime import date

Finding = tuple[str, int, int, str, float, str]
Header = Callable[[int], str] | None

MISREAD_DIGITS = {"O": "0", "o": "0", "D": "0", "Q": "0", "I": "1", "l": "1", "|": "1", "i": "1", "S": "5",
                  "s": "5", "B": "8", "Z": "2", "z": "2", "G": "6", "b": "6", "g": "9", "q": "9"}
NEAR_DIGIT = re.compile(r"(?<=\d)[OoDQIl|iSsBZzGbgq]|[OoDQIl|iSsBZzGbgq](?=\d)")
OCR_FIX_PENALTY = 0.85


def digit_view(text: str) -> str:
    for _ in range(2):
        text = NEAR_DIGIT.sub(lambda m: MISREAD_DIGITS[m.group()], text)
    return text


SSN = re.compile(r"(?<![\d-])(\d{3})([- ]?)(\d{2})\2(\d{4})(?![\d-])")
SSN_LABEL = re.compile(r"\b(?:ssn|ss\s?#|soc(?:ial)?\.?\s*sec(?:urity)?|tax\s*id|itin|tin)\b", re.I)
ITIN_GROUPS = set(range(50, 66)) | set(range(70, 89)) | {90, 91, 92} | set(range(94, 100))

ACCOUNT = re.compile(r"(?<!\d)0\d{10}(?!\d)")
ACCT_WORDS = r"(?:account|acct|acc|a/c|customer|cust)\.?[\s_.-]*"
ACCT_LABEL = re.compile(rf"\b{ACCT_WORDS}(?:(?:#|no\b\.?|num(?:ber)?|nbr|id\b)[\s.]*:?|:)", re.I)
ACCT_HEADING = re.compile(rf"\W*{ACCT_WORDS}(?:#|no\.?|num(?:ber)?|nbr|id)?\W*", re.I)
ACCT_DIGITS = r"[0-9OoIl|]+"
ACCT_AFTER_LABEL = re.compile(rf"[\s:#.\-]*(?:\([^)\n]{{0,20}}\)[\s:#.\-]*)?(?<![A-Za-z0-9-])({ACCT_DIGITS})(?![A-Za-z0-9-])")
ACCT_TOKEN = re.compile(rf"(?<![A-Za-z0-9-]){ACCT_DIGITS}(?![A-Za-z0-9-])")
MISREAD = str.maketrans("OoIl|", "00111")
BANK_WORDS = re.compile(r"\b(?:bank|checking|savings|deposit|dda|routing)\b", re.I)
CELL_EDGE = "\t\n,\""
CELL_BREAK = re.compile(r"[\t\n,]")

STATE_FORMATS = {
    "AL": [r"\d{1,8}"], "AK": [r"\d{1,7}"], "AZ": [r"[A-Z]\d{8}", r"[A-Z]{2}\d{2,5}", r"\d{9}"],
    "AR": [r"\d{4,9}"], "CA": [r"[A-Z]\d{7}"], "CO": [r"\d{9}", r"[A-Z]\d{3,6}", r"[A-Z]{2}\d{2,5}"],
    "CT": [r"\d{9}"], "DE": [r"\d{1,7}"], "DC": [r"\d{7}", r"\d{9}"], "FL": [r"[A-Z]\d{12}"],
    "GA": [r"\d{7,9}"], "HI": [r"[A-Z]\d{8}", r"\d{9}"], "ID": [r"[A-Z]{2}\d{6}[A-Z]", r"\d{9}"],
    "IL": [r"[A-Z]\d{11,12}"], "IN": [r"[A-Z]\d{9}", r"\d{9,10}"], "IA": [r"\d{9}", r"\d{3}[A-Z]{2}\d{4}"],
    "KS": [r"[A-Z]\d[A-Z]\d[A-Z]", r"[A-Z]\d{8}", r"\d{9}"], "KY": [r"[A-Z]\d{8,9}", r"\d{9}"],
    "LA": [r"\d{1,9}"], "ME": [r"\d{7,8}", r"\d{7}[A-Z]"], "MD": [r"[A-Z]\d{12}"], "MA": [r"[A-Z]\d{8}", r"\d{9}"],
    "MI": [r"[A-Z]\d{10}", r"[A-Z]\d{12}"], "MN": [r"[A-Z]\d{12}"], "MS": [r"\d{9}"],
    "MO": [r"[A-Z]\d{5,9}", r"[A-Z]\d{6}R", r"\d{8}[A-Z]{2}", r"\d{9}[A-Z]?"],
    "MT": [r"[A-Z]\d{8}", r"\d{9}", r"\d{13,14}"], "NE": [r"[A-Z]\d{6,8}"], "NV": [r"\d{9,10}", r"\d{12}", r"X\d{8}"],
    "NH": [r"\d{2}[A-Z]{3}\d{5}"], "NJ": [r"[A-Z]\d{14}"], "NM": [r"\d{8,9}"],
    "NY": [r"[A-Z]\d{7}", r"[A-Z]\d{18}", r"\d{8,9}", r"\d{16}"], "NC": [r"\d{1,12}"],
    "ND": [r"[A-Z]{3}\d{6}", r"\d{9}"], "OH": [r"[A-Z]\d{4,8}", r"[A-Z]{2}\d{3,7}", r"\d{8}"],
    "OK": [r"[A-Z]\d{9}", r"\d{9}"], "OR": [r"\d{1,9}", r"[A-Z]\d{6}", r"[A-Z]{2}\d{5}"], "PA": [r"\d{8}"],
    "RI": [r"\d{7}", r"[A-Z]\d{6}"], "SC": [r"\d{5,11}"], "SD": [r"\d{6,10}", r"\d{12}"], "TN": [r"\d{7,9}"],
    "TX": [r"\d{7,8}"], "UT": [r"\d{4,10}"], "VT": [r"\d{8}", r"\d{7}A"], "VA": [r"[A-Z]\d{8,11}", r"\d{9}"],
    "WA": [r"WDL[A-Z0-9]{9}", r"(?=[A-Z0-9]{12}$)[A-Z]{1,7}[A-Z0-9]{5,11}"],
    "WV": [r"\d{7}", r"[A-Z]{1,2}\d{5,6}"], "WI": [r"[A-Z]\d{13}"], "WY": [r"\d{9,10}"],
}
DL_VALUE = re.compile("|".join(f"(?:{p})" for ps in STATE_FORMATS.values() for p in ps))
DL_LABEL = re.compile(
    r"driver['’]?s?['’]?[\s_.-]*lic(?:ense)?"
    r"|operator['’]?s?[\s_.-]*lic(?:ense)?"
    r"|\b[do]ln\b"
    r"|\bd[./]?\s?l\.?(?:[\s_.-]?(?:no\b\.?|num(?:ber)?(?![a-z]))|\s?#|(?![a-z]))"
    r"|\blic(?:ense)?\.?\s?(?:#|no\b\.?|num(?:ber)?)",
    re.I)
STATE_ID_LABEL = re.compile(r"\b(?:state[\s_.-]*id|id[\s_.-]*card|identification[\s_.-]*(?:card|no\.?|num(?:ber)?|#))\b", re.I)
DL_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*(?![A-Za-z0-9])")
DASH_DATE = re.compile(r"\d{4}-\d{1,2}-\d{1,2}|\d{1,2}-\d{1,2}-(?:\d{2}|\d{4})")
LABEL_REACH = 40
LABEL_WORDS = {"number", "no", "num", "nbr", "id"}
OTHER_LABELS = {"ssn", "social", "ss", "dob", "birth", "phone", "tel", "cell", "mobile", "fax", "account", "acct",
                "routing", "aba", "bank", "card", "passport", "email", "itin", "tin"}
SSN_SHAPE = re.compile(r"\d{3}-\d{2}-\d{4}")

GAP = r"[\s:#.=\-]*(?:\([^)\n]{0,20}\)[\s:#.=\-]*)?"
QUAL = r"(?:[\s_.-]*(?:#|no\b\.?|num(?:ber)?|nbr))?"
DATE_TEXT = (r"\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{1,2}-\d{1,2}"
             r"|[A-Za-z]{3,9}\.?\s+\d{1,2},?\s+\d{4}|\d{1,2}\s+[A-Za-z]{3,9}\.?,?\s+\d{4}")
MONTHS = {m: i for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}
ABA_PREFIXES = {f"{n:02d}" for n in [*range(0, 13), *range(21, 33), *range(61, 73), 80]}
STREET_SUFFIX = (r"St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|Ct|Court|Hwy|Highway|Way|Pl|Place|"
                 r"Cir|Circle|Pkwy|Parkway|Trl|Trail|Ter|Terrace|Loop|Pike|Route|Rte")
ADDRESS = re.compile(
    r"\b\d{1,6}\s+(?:County\s+Road|CR|FM|State\s+Highway|SH|US\s+Highway|Hwy)\s+\d+[A-Z]?"
    r"|\b(?:RR|Rural\s+Route|HC)\s*\d+,?\s+Box\s+\d+"
    r"|\bP\.?\s?O\.?\s+Box\s+\d+"
    rf"|\b\d{{1,6}}\s+(?:[NSEW]\.?\s+)?(?:[A-Z][A-Za-z0-9.']*\s+){{1,4}}(?:{STREET_SUFFIX})\b\.?"
    r"(?:,?\s+(?:Apt|Unit|Suite|Ste|#)\s*[\w-]+)?")
ADDRESS_WORDS = {"street": "st", "avenue": "ave", "road": "rd", "boulevard": "blvd", "drive": "dr", "lane": "ln",
                 "court": "ct", "highway": "hwy", "place": "pl", "circle": "cir", "parkway": "pkwy", "trail": "trl",
                 "terrace": "ter", "route": "rte", "north": "n", "south": "s", "east": "e", "west": "w",
                 "suite": "ste", "apartment": "apt"}
OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4 = rf"{OCTET}(?:\.{OCTET}){{3}}"
HEX = "[0-9A-Fa-f]"
MAC_SHAPES = rf"{HEX}{{2}}(?::{HEX}{{2}}){{5}}|{HEX}{{2}}(?:-{HEX}{{2}}){{5}}|{HEX}{{4}}\.{HEX}{{4}}\.{HEX}{{4}}"
WORDS_VALUE = (rf"[A-Za-z0-9](?![\w/#.'-]*\s?:)[\w/#.'-]*"
               rf"(?: (?!(?i:{'|'.join(sorted(OTHER_LABELS))})\b)(?![\w/#.'-]+\s?:)[\w/#.'-]+){{0,3}}")


def address_key(value: str) -> str:
    words = [ADDRESS_WORDS.get(w, w) for w in re.findall(r"[a-z0-9]+", value.lower())]
    return re.sub(r"\bp o box\b", "po box", " ".join(words))


def _words(value: str) -> str:
    return " ".join(value.split()).lower()


def _with_digit(value: str) -> str | None:
    value = value.replace("-", "").rstrip("./").upper()
    return value if any(c.isdigit() for c in value) else None


def _iso_date(value: str) -> str | None:
    nums = [int(n) for n in re.findall(r"\d+", value)]
    word = re.search(r"[A-Za-z]{3,}", value)
    if word:
        month = MONTHS.get(word.group()[:3].lower())
        if not month or len(nums) != 2:
            return None
        day, year = nums
    elif len(nums) == 3:
        month, day, year = (nums[1], nums[2], nums[0]) if nums[0] > 31 else nums
    else:
        return None
    if year < 100:
        year += 2000 if year <= date.today().year % 100 else 1900
    try:
        d = date(year, month, day)
    except ValueError:
        return None
    return d.isoformat() if 1900 <= d.year <= date.today().year else None


def _aba(n: str) -> str | None:
    d = [int(c) for c in n]
    ok = n[:2] in ABA_PREFIXES and (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + d[2] + d[5] + d[8]) % 10 == 0
    return n if ok else None


def _nanp(n: str) -> str | None:
    n = re.sub(r"\D", "", n)
    n = n[1:] if len(n) == 11 and n[0] == "1" else n
    return n if len(n) == 10 and n[0] in "23456789" and n[3] in "23456789" else None


LABELED = [
    ("ROUTING_NUMBER", rf"\b(?:routing|aba|rtn|transit(?:\s*routing)?|r/t){QUAL}", r"\d{9}", _aba, 0.9,
     r"routing|\baba\b|\brtn\b|transit", True),
    ("BANK_ACCOUNT", rf"\b(?:bank|checking|savings|deposit|dda)\b[\s\w/]{{0,20}}?\b(?:account|acct|a/c)\b\.?{QUAL}",
     r"\d{4,17}", lambda v: v, 0.85, r"\b(?:bank|checking|savings|dda)\b.*\b(?:account|acct|a/c)\b", True),
    ("PASSPORT", rf"\bpassport\b{QUAL}", r"[A-Za-z]?\d{8,9}",
     lambda v: v.upper() if len(v) == 9 else None, 0.85, r"passport", False),
    ("STATE_ID", STATE_ID_LABEL.pattern, r"[A-Za-z0-9]+", lambda v: v.upper() if DL_VALUE.fullmatch(v.upper()) and len(v) >= 5 else None,
     0.85, STATE_ID_LABEL.pattern, False),
    ("DATE_OF_BIRTH", r"\b(?:d\.?\s?o\.?\s?b\.?|date\s+of\s+birth|birth\s*date|birthdate|born)(?![a-z])", DATE_TEXT,
     _iso_date, 0.9, r"\bdob\b|d\.o\.b|birth", True),
    ("PHONE_NUMBER", rf"\b(?:phone|ph|tel|telephone|cell|mobile|fax|contact\s+number){QUAL}",
     r"\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}", _nanp, 0.85, r"phone|\btel\b|cell|mobile|\bfax\b", True),
    ("CREDENTIAL", r"\b(?:password|passwd|pwd|passcode|pass\s*phrase|pin|wi-?fi\s*(?:key|password)|wpa2?\s*key"
                   r"|network\s*key|pppoe\s*(?:password|pass))\b(?=\s*[:=])", r"\S{4,64}", lambda v: v, 0.7,
     r"password|passwd|\bpin\b|passcode|wpa|wifi key", False),
    ("PERSON_NAME", r"\b(?:customer\s+name|account\s+holder|subscriber|cardholder|full\s+name|print\s+name|name)(?=\s*[:#-])",
     r"[A-Z][A-Za-z'.-]+(?: [A-Z][A-Za-z'.-]*){1,3}", _words, 0.6, r"\bname\b|holder|subscriber", False),
    ("CARD_SECURITY", r"\b(?:cvv2?|cvc2?|card\s+security\s+code|security\s+code)\b", r"\d{3,4}", lambda v: v, 0.85,
     r"\bcvv|\bcvc|security\s+code", True),
    ("CARD_SECURITY", r"\b(?:card\s+)?(?:exp(?:iration)?(?:\.?\s*date)?|expires|valid\s+thru)\b",
     r"(?:0?[1-9]|1[0-2])\s?/\s?(?:\d{4}|\d{2})(?![/\d])", lambda v: re.sub(r"\D", "", v), 0.55, r"\bexp", True),
    ("SERVICE_ADDRESS", r"\b(?:service|install(?:ation)?|e-?911|911|premises?)\s+(?:address|addr|location)\b",
     ADDRESS.pattern, address_key, 0.85, r"service\s+(?:address|location)|install|911|premise", False),
    ("IP_ADDRESS", r"\b(?:(?:static|wan|lan|public|private|assigned|customer|gateway|router)\s+)?ip(?:v[46])?"
                   r"(?:\s+(?:address|addr|block))?\b", rf"{IPV4}|{HEX}{{1,4}}(?::{HEX}{{0,4}}){{2,7}}", str.lower, 0.9,
     r"\bip\b|ip\s*addr", False),
    ("MAC_ADDRESS", r"\b(?:(?:cm|mta|hfc|ont|cpe|device|modem|router|wi-?fi)\s+)?mac(?:\s+(?:address|addr|id))?\b",
     rf"{MAC_SHAPES}|{HEX}{{12}}", lambda v: re.sub(r"[^0-9a-f]", "", v.lower()), 0.9, r"\bmac\b", False),
    ("EQUIPMENT_ID", rf"\b(?:(?:modem|ont|cpe|router|device|equipment|unit|mta|set[\s-]?top)\s+)?"
                     rf"(?:serial|s/n|sn|esn|imei|meid|iccid)(?![a-z]){QUAL}|\b(?:device|equipment|modem|ont|cpe)\s+id\b",
     r"[A-Za-z0-9][A-Za-z0-9-]{4,30}", _with_digit, 0.8,
     r"serial|\bs/n\b|\bsn\b|\besn\b|imei|meid|iccid|device\s+id|equipment\s+id", False),
    ("CIRCUIT_ID", r"\b(?:circuit|ckt)[\s_.-]*(?:id\b|#|no\b\.?|num(?:ber)?)", r"[A-Za-z0-9][A-Za-z0-9./-]{3,40}",
     _with_digit, 0.8, r"circuit|\bckt\b", False),
    ("USAGE", r"\b(?:data\s+usage|data\s+used|usage|minutes\s+used|minutes\s+of\s+use|total\s+minutes|mou)\b",
     r"\d[\d,]*(?:\.\d+)?\s?(?i:[KMGT]B|min(?:ute)?s?|hours?|hrs?)\b", lambda v: _words(v.replace(",", "")), 0.75,
     r"usage|minutes|\bmou\b", False),
    ("PAYMENT_HISTORY", r"\b(?:last\s+payment|previous\s+payment|payment\s+(?:received|amount|history|made|posted)|paid\s+on)\b",
     r"\$?\s?\d[\d,]*\.\d{2}|\d{1,2}/\d{1,2}/\d{2,4}", lambda v: re.sub(r"[\s$,]", "", v), 0.7,
     r"last\s+payment|payment\s+(?:received|amount|history|made|posted)|paid", False),
    ("SECURITY_ANSWER", r"\b(?:security\s+(?:answer|word|phrase)|secret\s+(?:answer|word)|(?:mother['’]?s\s+)?maiden\s+name"
                        r"|answer)(?=\s*[:=-])", WORDS_VALUE, _words, 0.7, r"security\s+answer|secret|maiden", False),
]


def _entry(pii_type, label, value, norm, conf, heading, on_view):
    return (pii_type, re.compile(label, re.I), re.compile(rf"{GAP}({value})(?![A-Za-z0-9])"), re.compile(value), norm,
            conf, re.compile(heading, re.I), on_view)


def custom_entry(code: str, words: list[str]):
    phrases = [r"[\s_.-]*".join(map(re.escape, w.split())) for w in words if w.split()]
    if not phrases:
        raise ValueError("a custom type needs the words printed next to it")
    label = rf"(?<![A-Za-z0-9])(?:{'|'.join(phrases)})(?![A-Za-z0-9])"
    return _entry(code, label + QUAL, WORDS_VALUE, _words, 0.8, label, False)


LABELED = [_entry(*e) for e in LABELED]

CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
CARD_LABEL = re.compile(r"\b(?:card|visa|master\s?card|amex|american\s+express|discover|credit|debit|cc\s?#)\b", re.I)
PHONE = re.compile(r"(?<![\d-])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[.-])\d{3}[.-]\d{4}(?![\d-])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CALL_TIME = re.compile(r"\b\d{1,2}:\d{2}\b|\b\d+\s*(?:min|mins|minutes|sec|secs)\b", re.I)
CPNI_WORDS = re.compile(r"call detail|minutes of use|long distance|toll charges?|calling plan|rate plan|caller id|"
                        r"call forwarding|call waiting|voice\s?mail|international calling|usage charges|"
                        r"three-way calling|speed dial", re.I)
AMOUNT_DUE = re.compile(r"\b(?:amount|balance|total)\s+due\b[^$\n]{0,20}\$\s?(\d[\d,]*\.\d{2})", re.I)
CALL_LINES_MIN = 3


def detect(text: str, header: Header = None, rules=None) -> Iterator[Finding]:
    view = digit_view(text)
    found: list[Finding] = []
    found += ssn_itin(text, view, header)
    found += accounts(text, header)
    found += [("CUSTOMER_ACCOUNT", s, e, v, c, m) for s, e, v, c, m in _unlabeled(ACCOUNT, text, view, 0.7, "regex")]
    found += drivers_licenses(text, header)
    found += labeled(text, view, header)
    if rules:
        found += labeled(text, view, header, rules.entries)
    found += cards(text, view)
    found += [("PHONE_NUMBER", s, e, n, c, m) for s, e, v, c, m in _unlabeled(PHONE, text, view, 0.8, "regex")
              if (n := _nanp(v))]
    found += [("EMAIL", m.start(), m.end(), m.group().lower(), 0.9, "regex") for m in EMAIL.finditer(text)]
    found += [("ADDRESS", m.start(), m.end(), address_key(m.group()), 0.7, "regex") for m in ADDRESS.finditer(text)]
    found += cpni(text)
    labeled_spans = [(f[1], f[2]) for f in found if f[5].startswith(("label", "column"))]
    skip = rules.skip if rules else ()
    for f in found:
        if f[5].startswith("regex") and any(s < f[2] and f[1] < e for s, e in labeled_spans):
            continue
        if (f[0], f[3]) in skip:
            continue
        yield f


def _unlabeled(pattern: re.Pattern, text: str, view: str, conf: float, method: str):
    for m in pattern.finditer(view):
        fixed = view[m.start():m.end()] != text[m.start():m.end()]
        yield m.start(), m.end(), m.group(), conf * (OCR_FIX_PENALTY if fixed else 1), method + ("+ocr_fix" if fixed else "")


def ssn_itin(text: str, view: str, header: Header) -> Iterator[Finding]:
    for start, end, value, conf, method in _unlabeled(SSN, text, view, 1.0, "regex+validate"):
        m = SSN.fullmatch(value)
        area, sep, group, serial = m.groups()
        labeled = bool(SSN_LABEL.search(text, _line_window(text, start), start)) or bool(
            header and SSN_LABEL.search(header(start)))
        base = 0.9 if sep or labeled else 0.5
        if labeled and not sep:
            method = method.replace("regex", "label" if not header else "column", 1)
        if valid_ssn(area, group, serial):
            yield "SSN", start, end, area + group + serial, round(base * conf, 3), method
        elif area[0] == "9" and int(group) in ITIN_GROUPS and serial != "0000":
            yield "ITIN", start, end, area + group + serial, round(min(base, 0.85) * conf, 3), method


def _line_window(text: str, start: int, reach: int = 30) -> int:
    return max(text.rfind("\n", 0, start) + 1, start - reach)


def valid_ssn(area: str, group: str, serial: str) -> bool:
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


def cards(text: str, view: str) -> Iterator[Finding]:
    for start, end, value, conf, method in _unlabeled(CARD, text, view, 1.0, "regex+luhn"):
        n = re.sub(r"\D", "", value)
        if not (13 <= len(n) <= 19 and _luhn(n)):
            continue
        if _card_brand(n):
            yield "CARD_NUMBER", start, end, n, round(0.9 * conf, 3), method
        elif CARD_LABEL.search(text, _line_window(text, start), start):
            yield "CARD_NUMBER", start, end, n, round(0.85 * conf, 3), method.replace("regex", "label", 1)


def _luhn(n: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(n)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def _card_brand(n: str) -> bool:
    size = len(n)
    return ((n[0] == "4" and size in (13, 16, 19)) or (size == 16 and (51 <= int(n[:2]) <= 55 or 2221 <= int(n[:4]) <= 2720))
            or (size == 15 and n[:2] in ("34", "37"))
            or (16 <= size <= 19 and (n.startswith(("6011", "65")) or 644 <= int(n[:3]) <= 649)))


def labeled(text: str, view: str, header: Header, entries=LABELED) -> Iterator[Finding]:
    for pii_type, label_re, after_re, value_re, norm, conf, heading_re, on_view in entries:
        source = view if on_view else text
        seen = set()
        for label in label_re.finditer(text):
            m = after_re.match(source, label.end(), _label_reach_end(text, label.start(), header))
            if m and (value := norm(m.group(1))) and m.span(1) not in seen:
                seen.add(m.span(1))
                fixed = source[m.start(1):m.end(1)] != text[m.start(1):m.end(1)]
                yield (pii_type, m.start(1), m.end(1), value, round(conf * (OCR_FIX_PENALTY if fixed else 1), 3),
                       "label" + ("+ocr_fix" if fixed else ""))
        if header:
            for cell in re.finditer(r"[^\t\n,]+", source):
                raw = cell.group().strip()
                if not raw or (cell.start(), cell.end()) in seen or not value_re.fullmatch(raw):
                    continue
                if any(heading_re.search(h) for h in header(cell.start()).split("\n")) and (value := norm(raw)):
                    start = cell.start() + cell.group().index(raw)
                    yield pii_type, start, start + len(raw), value, conf, "column"


def cpni(text: str) -> Iterator[Finding]:
    call_lines, offset = [], 0
    for line in text.split("\n"):
        if PHONE.search(digit_view(line)) and CALL_TIME.search(line):
            call_lines.append((offset, offset + len(line)))
        offset += len(line) + 1
    if len(call_lines) >= CALL_LINES_MIN:
        yield "CALL_DETAIL", call_lines[0][0], call_lines[-1][1], f"{len(call_lines)} call lines", 0.8, "cpni_call_table"
    hits = list(CPNI_WORDS.finditer(text))
    if len({h.group().lower() for h in hits}) >= 2:
        yield "SERVICE_PLAN", hits[0].start(), hits[0].end(), "service terms", 0.6, "cpni_vocabulary"
    for m in AMOUNT_DUE.finditer(text):
        yield "BILLING_AMOUNT", m.start(1), m.end(1), m.group(1).replace(",", ""), 0.6, "label"


def accounts(text: str, header: Header = None) -> Iterator[Finding]:
    seen = set()
    for label in ACCT_LABEL.finditer(text):
        if BANK_WORDS.search(text, _line_window(text, label.start(), 25), label.start()):
            continue
        m = ACCT_AFTER_LABEL.match(text, label.end(), _label_reach_end(text, label.start(), header))
        if m and (kind := _account(m.group(1))) and m.span(1) not in seen:
            seen.add(m.span(1))
            yield "CUSTOMER_ACCOUNT", m.start(1), m.end(1), kind[0], kind[1], "label" + kind[2]
    if header:
        for m in ACCT_TOKEN.finditer(text):
            whole_cell = (m.start() == 0 or text[m.start() - 1] in CELL_EDGE) and (
                m.end() == len(text) or text[m.end()] in CELL_EDGE)
            if not whole_cell or m.span() in seen:
                continue
            if any(ACCT_HEADING.fullmatch(h.strip()) for h in header(m.start()).split("\n")) and (kind := _account(m.group())):
                yield "CUSTOMER_ACCOUNT", m.start(), m.end(), kind[0], kind[1], "column" + kind[2]


def _account(raw: str) -> tuple[str, float, str] | None:
    if sum(c in "OoIl|" for c in raw) > 2:
        return None
    n = "".join(c for c in raw.translate(MISREAD) if c.isdigit())
    if not 4 <= len(n) <= 11:
        return None
    if len(n) == 11 and n[0] == "0":
        return n, 0.9, ""
    if len(n) == 10 and n[0] != "0":
        return "0" + n, 0.85, "+missing_zero"
    return n, 0.6, "+partial"


def drivers_licenses(text: str, header: Header = None) -> Iterator[Finding]:
    seen = set()
    for label in DL_LABEL.finditer(text):
        strong = _strong(label.group())
        for tok in DL_TOKEN.finditer(text, label.end(), _label_reach_end(text, label.start(), header)):
            if tok.start() - label.end() > LABEL_REACH or tok.group().lower() in OTHER_LABELS or SSN_SHAPE.fullmatch(tok.group()):
                break
            value = tok.group().replace("-", "").upper()
            if not _candidate(tok.group(), value, strong):
                if text.startswith(":", tok.end()) and value.lower() not in LABEL_WORDS:
                    break
                continue
            if DL_VALUE.fullmatch(value) and tok.span() not in seen:
                seen.add(tok.span())
                yield "DRIVERS_LICENSE", tok.start(), tok.end(), value, 0.85 if strong else 0.5, "label+state_format"
            break
    if header:
        for tok in DL_TOKEN.finditer(text):
            if tok.span() in seen:
                continue
            label = DL_LABEL.search(header(tok.start()))
            if not label:
                continue
            strong = _strong(label.group())
            value = tok.group().replace("-", "").upper()
            if _candidate(tok.group(), value, strong) and DL_VALUE.fullmatch(value) and not SSN_SHAPE.fullmatch(tok.group()):
                yield "DRIVERS_LICENSE", tok.start(), tok.end(), value, 0.85 if strong else 0.5, "column+state_format"


def _label_reach_end(text: str, label_start: int, header: Header) -> int:
    if header is None:
        return len(text)
    m = CELL_BREAK.search(text, label_start)
    return m.start() if m else len(text)


def _strong(label: str) -> bool:
    low = label.lower()
    return not (re.fullmatch(r"d[./]?\s?l\.?", low) or low.startswith("lic"))


def _candidate(raw: str, value: str, strong: bool) -> bool:
    return any(c.isdigit() for c in value) and len(value) >= (5 if strong else 7) and not DASH_DATE.fullmatch(raw)


def value_hmac(key: bytes, pii_type: str, normalized: str) -> str:
    return hmac.new(key, f"{pii_type}:{normalized}".encode(), hashlib.sha256).hexdigest()
