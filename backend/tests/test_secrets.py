import pytest

from reviewer.secrets import REDACTED, format_secret_findings, scan_and_redact_secrets


@pytest.mark.parametrize(
    "line, secret, kind",
    [
        ('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', "AKIAIOSFODNN7EXAMPLE", "AWS Access Key"),
        ('gh = "ghp_' + "a" * 36 + '"', "ghp_" + "a" * 36, "GitHub Token"),
        ('client = OpenAI(api_key="sk-proj-' + "b" * 30 + '")', "sk-proj-" + "b" * 30, "OpenAI API Key"),
        ('const key = "AIza' + "c" * 35 + '";', "AIza" + "c" * 35, "Google API Key"),
        ('SLACK = "xoxb-1234567890-abcdef"', "xoxb-1234567890-abcdef", "Slack Token"),
        ('h = {"Authorization": "Bearer abcdefghijklmnop123"}', "abcdefghijklmnop123", "Bearer Token"),
        ('private static final String DB_PASS = "super_secret_db_123";', "super_secret_db_123", "Hardcoded Credential"),
        ('{"password": "hunter2hunter2"}', "hunter2hunter2", "Hardcoded Credential"),
    ],
)
def test_detects_and_redacts(line, secret, kind):
    redacted, findings = scan_and_redact_secrets(line, "f.txt")

    assert secret not in redacted
    assert REDACTED in redacted
    assert kind in [f.type for f in findings]


def test_reports_correct_line_numbers():
    code = "x = 1\n\npassword = 'correcthorse'\n"
    _, findings = scan_and_redact_secrets(code, "app.py")

    assert [(f.file, f.line) for f in findings] == [("app.py", 3)]


def test_clean_code_is_untouched():
    code = "def add(a, b):\n    return a + b\n"
    redacted, findings = scan_and_redact_secrets(code, "math.py")

    assert redacted == code
    assert findings == []
    assert format_secret_findings(findings) == "No secrets detected."


def test_short_values_are_not_flagged():
    _, findings = scan_and_redact_secrets('password = "abc"', "a.py")
    assert findings == []


def test_redaction_only_touches_the_secret_line():
    code = 'name = "super_secret_db_123"\nDB_PASS = "super_secret_db_123"'
    redacted, findings = scan_and_redact_secrets(code, "c.py")

    first, second = redacted.split("\n")
    assert first == 'name = "super_secret_db_123"'
    assert second == f'DB_PASS = "{REDACTED}"'
    assert len(findings) == 1


def test_private_key_block_is_redacted():
    code = (
        "KEY = '''\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAs3cr3t\nmorekeymaterial\n"
        "-----END RSA PRIVATE KEY-----\n'''"
    )
    redacted, findings = scan_and_redact_secrets(code, "keys.py")

    assert "MIIEowIBAAKCAQEAs3cr3t" not in redacted
    assert findings[0].type == "Private Key"
    assert findings[0].line == 2


def test_multiple_secrets_on_one_line():
    line = 'creds = {"api_key": "abcdef123456", "secret": "zyxwvu987654"}'
    redacted, findings = scan_and_redact_secrets(line, "c.py")

    assert "abcdef123456" not in redacted and "zyxwvu987654" not in redacted
    assert len(findings) == 2
