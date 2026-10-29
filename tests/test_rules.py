import json

import pytest

from piiscan import rules
from piiscan.detect import detect, value_hmac
from piiscan.rules import NONE, Rules, bypass_keys

KEY = b"r" * 32


def types_in(text, r):
    return {(t, v) for t, _, _, v, _, _ in detect(text, None, r)}


def test_names_are_grouped_with_customs_inside_their_group_and_none_last():
    r = Rules()
    r.add_type("Other", "Employee ID")
    r.add_type("CPNI", "Port-out PIN", "port pin, transfer pin")
    names = list(r.names())
    groups = [n.split(":")[0] for n in names]
    assert groups == sorted(groups, key=rules.ORDER.index) and names[-1] == NONE
    assert names.index("CPNI: Port-out PIN") > names.index("CPNI: Security answer")
    assert names.index("CPNI: Port-out PIN") < names.index("Other: Name")
    assert names.index("Other: Employee ID") > names.index("Other: Email")
    assert set(r.codes()) == set(rules.LABEL_TYPES.values()) - {"NONE"} | {"EMPLOYEE_ID", "PORT_OUT_PIN"}
    assert r.codes() == sorted(r.codes())


def test_every_type_has_its_own_color():
    r = Rules()
    for i in range(len(rules.CUSTOM_COLORS)):
        r.add_type("Other", f"Custom {chr(65 + i)}")
    codes = list(r.names().values())
    assert len({r.color(c) for c in codes}) == len(codes)
    assert r.color("NOT_A_TYPE") == rules.COLORS["NONE"]


@pytest.mark.parametrize("group, name, words", [
    ("Nope", "Employee ID", ""),
    ("Other", "   ", ""),
    ("Other", "SSN", ""),
    ("CPNI", "Phone #", ""),
    ("Other", "Employee-ID", ""),
    ("CPNI", "Employee ID", ""),
    ("Other", "Badge", ",  , #"),
])
def test_add_type_rejects_bad_input(group, name, words):
    r = Rules()
    r.add_type("Other", "Employee ID")
    with pytest.raises(ValueError):
        r.add_type(group, name, words)
    assert [t["code"] for t in r.types] == ["EMPLOYEE_ID"]


def test_add_type_words_default_to_the_name():
    r = Rules()
    rec = r.add_type("Other", "  Employee   ID ")
    assert rec["name"] == "Employee ID" and rec["code"] == "EMPLOYEE_ID" and rec["words"] == ["employee id"]
    assert r.add_type("Other", "Badge", "Badge #, Badge  Number")["words"] == ["badge #", "badge number"]
    assert ("EMPLOYEE_ID", "4471") in types_in("Employee ID: 4471", r)


def test_rules_persist_atomically(tmp_path):
    path = tmp_path / "data" / "rules.json"
    r = Rules(path)
    r.add_type("CPNI", "Port-out PIN", "port pin")
    r.add_bypass(["PHONE_NUMBER"], "(800) 555-1234")
    r.add_bypass(["ADDRESS"], "1 Company Plaza Dr")
    assert not list(path.parent.glob("*.tmp"))
    again = Rules(path)
    assert again.data() == json.loads(path.read_text()) == r.data()
    assert again.skip == r.skip and len(again.entries) == 1
    again.remove_type("PORT_OUT_PIN")
    again.remove_bypass(0)
    final = Rules(path)
    assert final.types == [] and [b["value"] for b in final.bypass] == ["1 Company Plaza Dr"]
    assert not final.skips("PHONE_NUMBER", "8005551234")


def test_missing_file_means_no_rules(tmp_path):
    r = Rules(tmp_path / "rules.json")
    assert r.types == [] and r.bypass == [] and r.skip == set() and r.entries == []
    assert not (tmp_path / "rules.json").exists()


@pytest.mark.parametrize("entered", ["(800) 555-1234", "800.555.1234", "1-800-555-1234", "8005551234"])
def test_company_phone_is_bypassed_in_every_form(entered):
    r = Rules()
    r.add_bypass(["PHONE_NUMBER"], entered)
    for text in ["Call (800) 555-1234", "Phone: 800.555.1234", "tel 1-800-555-1234", "Phone 8005551234"]:
        assert not any(t == "PHONE_NUMBER" for t, _ in types_in(text, r)), text
    assert ("PHONE_NUMBER", "5125550199") in types_in("Call (800) 555-1234 or 512-555-0199", r)


@pytest.mark.parametrize("entered, text", [
    ("123 Main Street", "mail to 123 Main St."),
    ("123 Main St.", "remit to 123 Main Street"),
    ("P.O. Box 77", "PO Box 77"),
    ("PO Box 77", "P.O. Box 77"),
    ("123 Main Street", "Service Address: 123 Main St"),
])
def test_company_address_is_bypassed_in_every_form(entered, text):
    r = Rules()
    r.add_bypass(["ADDRESS"], entered)
    assert not any(t in ("ADDRESS", "SERVICE_ADDRESS") for t, _ in types_in(text, r))
    assert any(t == "ADDRESS" for t, _ in types_in("ship to 9 Oak Ave", r))


def test_service_address_bypass_covers_plain_addresses():
    assert ("ADDRESS", "123 main st") in bypass_keys(["SERVICE_ADDRESS"], "123 Main Street")


def test_also_keys_and_none_handling():
    r = Rules()
    r.add_bypass(["CUSTOMER_ACCOUNT", "NONE"], "1234567890", also=[("CUSTOMER_ACCOUNT", "01234567890")])
    assert r.bypass[0]["types"] == ["CUSTOMER_ACCOUNT"]
    assert r.skips("CUSTOMER_ACCOUNT", "01234567890")
    assert not any(t == "CUSTOMER_ACCOUNT" for t, _ in types_in("Account Number: 1234567890", r))
    for types, value in ((["NONE"], "8005551234"), ([], "8005551234"), (["PHONE_NUMBER"], "   ")):
        with pytest.raises(ValueError):
            r.add_bypass(types, value)
    assert len(r.bypass) == 1


def test_bypass_is_per_type():
    r = Rules()
    r.add_bypass(["PHONE_NUMBER"], "5125550199")
    assert not r.skips("SSN", "5125550199") and r.skips("PHONE_NUMBER", "5125550199")


def test_hmacs_cover_every_skipped_value():
    r = Rules()
    r.add_bypass(["PHONE_NUMBER"], "(800) 555-1234")
    r.add_bypass(["EMAIL"], "Support@Example.com")
    assert r.hmacs(KEY) == {value_hmac(KEY, t, n) for t, n in r.skip}
    assert value_hmac(KEY, "PHONE_NUMBER", "8005551234") in r.hmacs(KEY)
    assert value_hmac(KEY, "EMAIL", "support@example.com") in r.hmacs(KEY)


def test_worker_data_round_trip():
    r = Rules()
    r.add_type("Other", "Employee ID")
    r.add_bypass(["PHONE_NUMBER"], "(800) 555-1234")
    copy = Rules(data=json.loads(json.dumps(r.data())))
    assert copy.skip == r.skip and types_in("Employee ID: 4471 Phone (800) 555-1234", copy) == {("EMPLOYEE_ID", "4471")}
