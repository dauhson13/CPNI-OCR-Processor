import re

import pytest

from piiscan.detect import DL_VALUE, STATE_FORMATS, detect

STATE_EXAMPLES = {
    "AL": "1234567", "AK": "1234567", "AZ": "A12345678", "AR": "123456789", "CA": "A1234567", "CO": "123456789",
    "CT": "123456789", "DE": "1234567", "DC": "1234567", "FL": "A123456789012", "GA": "123456789", "HI": "H12345678",
    "ID": "AB123456C", "IL": "A12345678901", "IN": "1234567890", "IA": "123AB4567", "KS": "K12345678",
    "KY": "K12345678", "LA": "123456789", "ME": "1234567X", "MD": "M123456789012", "MA": "S12345678",
    "MI": "M1234567890", "MN": "M123456789012", "MS": "123456789", "MO": "M123456R", "MT": "1234567890123",
    "NE": "N1234567", "NV": "X12345678", "NH": "12ABC34567", "NJ": "N12345678901234", "NM": "12345678",
    "NY": "N1234567", "NC": "123456789012", "ND": "ABC123456", "OH": "OH123456", "OK": "O123456789",
    "OR": "OR12345", "PA": "12345678", "RI": "R123456", "SC": "1234567890", "SD": "123456789012", "TN": "12345678",
    "TX": "12345678", "UT": "1234567890", "VT": "1234567A", "VA": "V123456789", "WA": "WDL12345ABCD",
    "WV": "AB12345", "WI": "W1234567890123", "WY": "1234567890",
}


def dls(text, header=None):
    return [(v, c) for t, _, _, v, c, _ in detect(text, header) if t == "DRIVERS_LICENSE"]


def test_all_50_states_and_dc():
    assert set(STATE_FORMATS) == set(STATE_EXAMPLES) and len(STATE_FORMATS) == 51
    for state, example in STATE_EXAMPLES.items():
        assert any(re.fullmatch(p, example) for p in STATE_FORMATS[state]), state
        assert DL_VALUE.fullmatch(example), state
        assert dls(f"Driver's License ({state}): {example}") == [(example, 0.85)], state


@pytest.mark.parametrize("text, expected", [
    ("Driver's License #: D123-4567-8901", "D12345678901"),
    ("Driver’s License Number: a1234567", "A1234567"),
    ("DL#A1234567", "A1234567"),
    ("TX DLN 12345678", "12345678"),
    ("dl_number: A1234567", "A1234567"),
    ("Operator's License No. 123456789", "123456789"),
    ("Driver License\nA1234567", "A1234567"),
    ("Driver's License (exp 05/01/2027): D1234567", "D1234567"),
    ("Driver's License Exp 2027-05-01 D1234567", "D1234567"),
])
def test_labeled_values(text, expected):
    assert dls(text) == [(expected, 0.85)]


@pytest.mark.parametrize("text", [
    "DL: 1000 Mbps", "DL/UL: 1000/100", "Speed test DL 940 UL 35", "DL 100000 kbps",
    "License key: ABCD-1234-EFGH", "Invoice A1234567 total 12345678",
    "Driver's License: N/A   Phone: 5551234567",
    "Driver's License: ________",
])
def test_not_licenses(text):
    assert dls(text) == []


def test_only_the_value_right_after_the_label():
    assert dls("DL#: D1234567 Phone 5551234567") == [("D1234567", 0.85)]


def test_weak_labels_go_to_review():
    assert dls("DL: 1000000") == [("1000000", 0.5)]
    assert dls("License #: 12345678") == [("12345678", 0.5)]


def accts(text, header=None):
    return [(v, c, m) for t, _, _, v, c, m in detect(text, header) if t == "CUSTOMER_ACCOUNT"]


@pytest.mark.parametrize("text, expected", [
    ("Acct #: 01234567890", ("01234567890", 0.9, "label")),
    ("Account Number: 1234567890", ("01234567890", 0.85, "label+missing_zero")),
    ("Account No. (last 4): 7890", ("7890", 0.6, "label+partial")),
    ("Account No 456789", ("456789", 0.6, "label+partial")),
    ("Acct: O123456789O", ("01234567890", 0.9, "label")),
    ("Account Number\n1234567890", ("01234567890", 0.85, "label+missing_zero")),
    ("Acct: 01234567890", ("01234567890", 0.9, "label")),
])
def test_account_labels(text, expected):
    assert accts(text) == [expected]


@pytest.mark.parametrize("text", [
    "account balance: 1234.56", "Customer: Pat Doe 5551234567", "Accounts Payable 2024", "Acct: lol", "Acct #: 12",
    "Account No: 555-123-4567",
])
def test_not_accounts(text):
    assert accts(text) == []


def test_unlabeled_full_account():
    assert accts("ref 01234567890") == [("01234567890", 0.7, "regex")]


def test_account_column_heading():
    text = "1234567890\t1234\t2015"
    heads = {0: "Report\nAccount #", 11: "Account Balance", 16: "Customer Since"}
    assert accts(text, lambda s: heads[0 if s < 11 else 11 if s < 16 else 16]) == [
        ("01234567890", 0.85, "column+missing_zero")]


def test_column_heading():
    heading = {0: "Name", 9: "Drivers License"}
    text = "Pat Doe\tA1234567"
    assert dls(text, lambda start: heading[0 if start < 8 else 9]) == [("A1234567", 0.85)]
    assert dls("1000", lambda start: "DL") == []


def kinds(text, header=None):
    return {(t, v) for t, _, _, v, _, _ in detect(text, header)}


def aba(prefix8):
    d = [int(c) for c in prefix8]
    check = (10 - (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + d[2] + d[5]) % 10) % 10
    return prefix8 + str(check)


@pytest.mark.parametrize("text, expected", [
    ("ITIN 912-70-1234", ("ITIN", "912701234")),
    ("Visa 4111 1111 1111 1111", ("CARD_NUMBER", "4111111111111111")),
    ("Card #: 1234 5678 1234 5670", ("CARD_NUMBER", "1234567812345670")),
    (f"Routing #: {aba('01100001')}", ("ROUTING_NUMBER", aba("01100001"))),
    ("Bank Account Number: 123456789012", ("BANK_ACCOUNT", "123456789012")),
    ("Checking acct #: 4455667788", ("BANK_ACCOUNT", "4455667788")),
    ("call (512) 555-0199 today", ("PHONE_NUMBER", "5125550199")),
    ("Phone: 5125550199", ("PHONE_NUMBER", "5125550199")),
    ("email pat.doe@example.com", ("EMAIL", "pat.doe@example.com")),
    ("DOB: 04/15/1982", ("DATE_OF_BIRTH", "1982-04-15")),
    ("Date of Birth: April 15, 1982", ("DATE_OF_BIRTH", "1982-04-15")),
    ("Passport No: 123456789", ("PASSPORT", "123456789")),
    ("Passport #: a12345678", ("PASSPORT", "A12345678")),
    ("State ID: A1234567", ("STATE_ID", "A1234567")),
    ("Wi-Fi Password: Summer2024!", ("CREDENTIAL", "Summer2024!")),
    ("Customer Name: Pat Q. Doe", ("PERSON_NAME", "pat q. doe")),
    ("ship to 123 Main St Apt 4", ("ADDRESS", "123 main st apt 4")),
    ("RR 2 Box 15", ("ADDRESS", "rr 2 box 15")),
    ("PO Box 77", ("ADDRESS", "po box 77")),
    ("1200 County Road 45", ("ADDRESS", "1200 county road 45")),
    ("Amount Due: $1,045.99", ("BILLING_AMOUNT", "1045.99")),
])
def test_more_types(text, expected):
    assert expected in kinds(text)


@pytest.mark.parametrize("text, absent", [
    ("Visa 4111 1111 1111 1112", "CARD_NUMBER"),
    ("ref 1234 5678 1234 5670", "CARD_NUMBER"),
    (f"ref {aba('01100001')}", "ROUTING_NUMBER"),
    ("Routing #: 011000010", "ROUTING_NUMBER"),
    ("Phone: 123-456-7890", "PHONE_NUMBER"),
    ("meeting on 04/15/1982", "DATE_OF_BIRTH"),
    ("DOB: 13/45/1982", "DATE_OF_BIRTH"),
    ("please enter your password to continue", "CREDENTIAL"),
    ("File name: report.pdf", "PERSON_NAME"),
    ("State ID: A1234567", "DRIVERS_LICENSE"),
])
def test_more_types_not_found(text, absent):
    assert not any(t == absent for t, _ in kinds(text))


def test_bank_account_is_not_a_customer_account():
    found = kinds("Bank Account Number: 01234567890")
    assert ("BANK_ACCOUNT", "01234567890") in found and not any(t == "CUSTOMER_ACCOUNT" for t, _ in found)


def test_ocr_misread_is_corrected_and_marked():
    (_, _, _, value, conf, method), = [f for f in detect("Customer SSN: 123-45-67B9") if f[0] == "SSN"]
    assert value == "123456789" and method.endswith("+ocr_fix") and conf == round(0.9 * 0.85, 3)


def test_ssn_label_makes_bare_digits_convincing():
    assert [c for t, *_, c, _ in detect("SSN 123456789") if t == "SSN"] == [0.9]
    assert [c for t, *_, c, _ in detect("ref 123456789") if t == "SSN"] == [0.5]
    assert [c for t, *_, c, _ in detect("SSN 123-45-6789\nref 234567890") if t == "SSN"] == [0.9, 0.5]


def test_cpni_call_table_and_service_terms():
    calls = "\n".join(f"10/0{i} 09:1{i} (512) 555-010{i} {i + 2} min" for i in range(1, 5))
    found = {t for t, *_ in detect(calls + "\nRate plan includes voicemail and caller ID")}
    assert {"CALL_DETAIL", "SERVICE_PLAN"} <= found
    assert "CALL_DETAIL" not in {t for t, *_ in detect("call me at (512) 555-0101 at 09:15")}


def test_column_headings_for_more_types():
    text = "Pat Doe\t04/15/1982\t5125550199"
    heads = ["Customer Name", "DOB", "Cell Phone"]
    col = lambda s: heads[text.count("\t", 0, s)]
    found = kinds(text, col)
    assert {("DATE_OF_BIRTH", "1982-04-15"), ("PHONE_NUMBER", "5125550199"), ("PERSON_NAME", "pat doe")} <= found


def test_regressions_from_eval():
    assert ("PASSPORT", "G72446885") in kinds("Passport No: G72446885")
    assert ("CUSTOMER_ACCOUNT", "0141") in kinds("Routing #: 063143014\nAccount No (last 4): 0141")


@pytest.mark.parametrize("text", [
    "Driver's License SSN 123-45-6789",
    "Driver's License: ____  SSN: 123-45-6789",
    "Driver's License\nSSN\n123-45-6789",
    "DL# 123-45-6789",
    "Driver's License Social Security 123456789",
])
def test_ssn_is_never_taken_as_a_drivers_license(text):
    found = kinds(text)
    assert not any(t == "DRIVERS_LICENSE" for t, _ in found)
    assert any(t == "SSN" for t, _ in found)


def test_license_and_ssn_side_by_side():
    found = kinds("Driver's License: D1234567   SSN: 123-45-6789")
    assert ("DRIVERS_LICENSE", "D1234567") in found and ("SSN", "123456789") in found
