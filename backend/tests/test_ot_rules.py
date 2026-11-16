from pathlib import Path

import pytest

from reviewer.rules import FileContext, rules_by_pack, run_rules
from reviewer.rules.ot_ics import is_ot_file

FIXTURES = Path(__file__).parent / "fixtures" / "ot"
OT_RULES = rules_by_pack("ot_ics")
RULE_IDS = [r.id for r in OT_RULES]


def scan(path: Path):
    ctx = FileContext(path.name, "PYTHON", path.read_text(encoding="utf-8"))
    return run_rules(ctx, OT_RULES)


def scan_text(code: str, language: str = "JAVASCRIPT", name: str = "app.js"):
    return run_rules(FileContext(name, language, code), OT_RULES)


def test_pack_has_ten_rules_with_complete_metadata():
    assert RULE_IDS == [f"OT-{i:03d}" for i in range(1, 11)]
    for rule in OT_RULES:
        assert rule.cwe.startswith("CWE-")
        assert rule.stride and rule.description and rule.remediation and rule.references


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_vulnerable_fixture_triggers_rule(rule_id):
    findings = scan(FIXTURES / f"{rule_id}_vulnerable.py")
    assert rule_id in {f.rule_id for f in findings}


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_safe_fixture_triggers_no_ot_rule(rule_id):
    findings = scan(FIXTURES / f"{rule_id}_safe.py")
    assert findings == [], [(f.rule_id, f.line) for f in findings]


def test_findings_point_to_the_right_line():
    lines = {f.rule_id: f.line for f in scan(FIXTURES / "OT-001_vulnerable.py")}
    assert lines == {"OT-001": 7}


def test_mqtt_reports_connection_and_wildcard_separately():
    findings = [f for f in scan(FIXTURES / "OT-005_vulnerable.py") if f.rule_id == "OT-005"]

    assert [f.line for f in findings] == [4, 5]
    assert "without TLS" in findings[0].description and "without credentials" in findings[0].description
    assert "Wildcard" in findings[1].description


def test_modbus_alias_import_is_resolved():
    code = "from pymodbus.client import ModbusTcpClient as MB\nc = MB('plc', timeout=2)\n"
    assert {f.rule_id for f in scan_text(code, "PYTHON", "a.py")} == {"OT-001"}


def test_dnp3_tcp_channel_is_flagged():
    code = "from pydnp3 import asiodnp3\nchannel = manager.AddTCPClient('outstation', level, retry, '10.1.1.4', '0.0.0.0', 20000, listener)\n"
    ids = {f.rule_id for f in scan_text(code, "PYTHON", "dnp.py")}
    assert {"OT-003", "OT-007"} <= ids


def test_opcua_explicit_none_policy_is_flagged():
    code = "server.set_security_policy([ua.SecurityPolicyType.NoSecurity])\n"
    assert [f.rule_id for f in scan_text(code, "PYTHON", "srv.py")] == ["OT-004"]


def test_write_with_constant_value_is_not_flagged():
    assert scan_text("client.write_coil(10, True)\n", "PYTHON", "a.py") == []


def test_write_bounded_with_min_max_is_not_flagged():
    code = "def f(c, v):\n    v = max(0, min(v, 100))\n    c.write_register(1, v)\n"
    assert scan_text(code, "PYTHON", "a.py") == []


def test_default_credentials_as_keywords_and_constants():
    code = 'USERNAME = "admin"\nPASSWORD = ""\nclient = Device(host, username="root", password="root")\n'
    findings = scan_text(code, "PYTHON", "a.py")
    assert sorted(f.line for f in findings if f.rule_id == "OT-008") == [2, 3]


def test_hardcoded_ip_with_industrial_port_in_url():
    code = 'const url = "opc.tcp://10.20.0.7:4840";\n'
    findings = scan_text(code)
    assert [f.rule_id for f in findings] == ["OT-007"]
    assert "OPC UA" in findings[0].description


def test_loopback_and_unspecified_addresses_are_ignored():
    assert scan_text('server.listen("0.0.0.0", 502); probe("127.0.0.1:502")\n') == []


@pytest.mark.parametrize(
    "code, rule_id",
    [
        ("const c = mqtt.connect('mqtt://broker.local');", "OT-005"),
        ("https.get(url, { rejectUnauthorized: false });", "OT-009"),
        ("tls.Config{InsecureSkipVerify: true}", "OT-009"),
        ("client.connectTCP('plc.local', { port: 502 });", "OT-001"),
        ("fetch('http://192.168.1.50/api/relay')", "OT-006"),
        ("client.writeRegister(4, req.body.value)", "OT-002"),
    ],
)
def test_text_rules_for_other_languages(code, rule_id):
    assert rule_id in {f.rule_id for f in scan_text(code)}


def test_text_fallback_for_unparseable_python():
    code = "def broken(:\n    requests.get(url, verify=False)\n"
    findings = scan_text(code, "PYTHON", "a.py")
    assert [(f.rule_id, f.engine) for f in findings] == [("OT-009", "text")]


def test_ot_file_detection():
    assert is_ot_file(FileContext("a.py", "PYTHON", "import pymodbus\n"))
    assert is_ot_file(FileContext("a.js", "JAVASCRIPT", "// read the substation PLC\n"))
    assert not is_ot_file(FileContext("a.py", "PYTHON", "print('hello')\n"))
