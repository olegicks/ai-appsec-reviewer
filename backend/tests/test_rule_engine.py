import ast

import pytest

from reviewer.findings import Finding, dedupe, max_severity, min_confidence, normalize_cwe
from reviewer.rules import FileContext, Match, Rule, bandit_findings, run_rules, secret_findings
from reviewer.rules import python_ast as pa
from reviewer.rules.text import grep
from reviewer.secrets import SecretFinding, scan_and_redact_secrets


def make_rule(**overrides):
    base = dict(
        id="T-001",
        title="Test rule",
        category="test",
        severity_floor="MEDIUM",
        cwe="CWE-319",
        stride=("Tampering",),
        description="Test description.",
        remediation="Fix it.",
    )
    base.update(overrides)
    return Rule(**base)


def eval_calls(ctx):
    for call in pa.iter_calls(ctx.tree):
        if pa.short_name(call) == "eval":
            yield Match(line=call.lineno)


def eval_text(ctx):
    yield from grep(ctx, r"\beval\(")


EVAL_RULE = make_rule(match_ast=eval_calls, match_text=eval_text)


def test_ast_matcher_is_used_for_parseable_python():
    ctx = FileContext("app.py", "PYTHON", "x = 1\n# eval(y) in a comment\nresult = eval(data)\n")
    findings = run_rules(ctx, [EVAL_RULE])

    assert [(f.line, f.engine) for f in findings] == [(3, "python_ast")]
    assert findings[0].snippet == "result = eval(data)"


def test_text_matcher_is_used_for_other_languages_and_broken_python():
    js = FileContext("app.js", "JAVASCRIPT", "const r = eval(input);\n")
    broken = FileContext("bad.py", "PYTHON", "def oops(:\n    eval(x)\n")

    assert [(f.line, f.engine) for f in run_rules(js, [EVAL_RULE])] == [(1, "text")]
    assert [(f.line, f.engine) for f in run_rules(broken, [EVAL_RULE])] == [(2, "text")]


def test_text_matcher_skips_comments():
    ctx = FileContext("app.js", "JAVASCRIPT", "// eval(x)\n")
    assert run_rules(ctx, [EVAL_RULE]) == []


def test_language_filter():
    rule = make_rule(languages=("PYTHON",), match_text=eval_text)
    assert run_rules(FileContext("a.js", "JAVASCRIPT", "eval(x)"), [rule]) == []


def test_finding_carries_rule_metadata():
    ctx = FileContext("app.py", "PYTHON", "eval(data)\n")
    f = run_rules(ctx, [EVAL_RULE])[0]

    assert (f.rule_id, f.title, f.category, f.cwe, f.stride) == ("T-001", "Test rule", "test", "CWE-319", ["Tampering"])
    assert f.severity == "MEDIUM" and f.confidence == "HIGH"


def test_match_can_raise_severity_and_lower_confidence_but_not_the_reverse():
    def matcher(ctx):
        yield Match(line=1, severity="CRITICAL", confidence="LOW")
        yield Match(line=2, severity="INFO", confidence="HIGH", detail="Extra detail.")

    rule = make_rule(confidence="MEDIUM", match_text=matcher)
    first, second = run_rules(FileContext("a.txt", "TEXT", "a\nb"), [rule])

    assert (first.severity, first.confidence) == ("CRITICAL", "LOW")
    assert (second.severity, second.confidence) == ("MEDIUM", "MEDIUM")
    assert second.description.endswith("Extra detail.")


def test_one_finding_per_rule_per_line():
    def matcher(ctx):
        yield Match(line=1)
        yield Match(line=1)

    assert len(run_rules(FileContext("a", "TEXT", "x"), [make_rule(match_text=matcher)])) == 1


def test_fingerprint_is_stable_and_whitespace_insensitive():
    a = Finding("R", "t", "c", "text", "LOW", "LOW", "f.py", 3, snippet="x  =  eval(y)")
    b = Finding("R", "t", "c", "text", "LOW", "LOW", "f.py", 3, snippet="x = eval(y)")
    c = Finding("R", "t", "c", "text", "LOW", "LOW", "f.py", 4, snippet="x = eval(y)")

    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != c.fingerprint
    assert len(a.fingerprint) == 16


def test_dedupe_merges_engines_on_same_line_and_cwe():
    rule_f = Finding("OT-009", "No cert check", "ot_ics", "python_ast", "HIGH", "HIGH", "a.py", 5, cwe="CWE-295")
    bandit_f = Finding("B501", "request_with_no_cert_validation", "sast", "bandit", "HIGH", "HIGH", "a.py", 5,
                       cwe="295", user_input=True)
    other = Finding("B602", "shell", "sast", "bandit", "HIGH", "HIGH", "a.py", 9, cwe="CWE-78")

    merged = dedupe([bandit_f, rule_f, other, rule_f])

    assert len(merged) == 2
    assert merged[0].rule_id == "OT-009"
    assert merged[0].engines == ["bandit", "python_ast"]
    assert merged[0].user_input is True


@pytest.mark.parametrize("value, expected", [("CWE-79", "CWE-79"), ("cwe 89", "CWE-89"), (78, "CWE-78"), ("", ""), (None, "")])
def test_normalize_cwe(value, expected):
    assert normalize_cwe(value) == expected


def test_severity_and_confidence_helpers():
    assert max_severity("LOW", "CRITICAL", "MEDIUM") == "CRITICAL"
    assert max_severity("bogus") == "INFO"
    assert min_confidence("HIGH", "LOW") == "LOW"


def test_bandit_output_is_normalised():
    ctx = FileContext("app/db.py", "PYTHON", "import subprocess\nsubprocess.call(cmd, shell=True)\n")
    raw = [{"line_number": 2, "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true",
            "issue_text": "shell=True", "issue_severity": "HIGH", "issue_confidence": "HIGH", "cwe": 78}]

    f = bandit_findings(ctx, raw)[0]

    assert (f.rule_id, f.engine, f.category, f.cwe, f.severity) == ("B602", "bandit", "sast", "CWE-78", "HIGH")
    assert f.snippet == "subprocess.call(cmd, shell=True)"
    assert f.user_input is True


def test_secret_findings_use_redacted_excerpts():
    code = 'API = "AKIAIOSFODNN7EXAMPLE"\n'
    redacted, raw = scan_and_redact_secrets(code, "cfg.py")
    ctx = FileContext("cfg.py", "PYTHON", redacted)

    f = secret_findings(ctx, raw)[0]

    assert f.rule_id == "SECRET-AWS-ACCESS-KEY"
    assert "AKIAIOSFODNN7EXAMPLE" not in f.snippet
    assert f.cwe == "CWE-798"


def test_private_key_redaction_keeps_line_numbers():
    code = "a = 1\nKEY = '''-----BEGIN RSA PRIVATE KEY-----\nAAAA\nBBBB\n-----END RSA PRIVATE KEY-----'''\nb = eval(x)\n"
    redacted, _ = scan_and_redact_secrets(code, "k.py")

    assert redacted.count("\n") == code.count("\n")
    assert redacted.split("\n")[5] == "b = eval(x)"


def test_ast_helpers():
    tree = ast.parse("from pymodbus.client import ModbusTcpClient\nc = ModbusTcpClient('10.0.0.5', port=502)\n")
    call = next(c for c in pa.iter_calls(tree))

    assert pa.short_name(call) == "ModbusTcpClient"
    assert pa.const_value(pa.arg(call, 1, "port")) == 502
    assert {"pymodbus", "pymodbus.client"} <= pa.imported_modules(tree)


def test_secret_finding_dataclass_str():
    assert str(SecretFinding("a.py", 3, "Bearer Token")) == "[a.py] Line 3: Bearer Token detected."
