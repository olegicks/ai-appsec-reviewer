"""OT / ICS & IoT rule pack: insecure industrial protocols and field-device access patterns.

Rules are deliberately explainable heuristics. They look for well-known library calls and
configuration literals; they do not prove exploitability.
"""
import ast
import re
from typing import Iterator

from . import python_ast as pa
from .base import FileContext, Match, Rule
from .text import grep, is_comment

PACK = "ot_ics"
CATEGORY = "ot_ics"

INDUSTRIAL_PORTS = {
    502: "Modbus/TCP",
    2404: "IEC 60870-5-104",
    20000: "DNP3",
    102: "S7comm / IEC 61850 MMS",
    4840: "OPC UA",
    1883: "MQTT",
}

IPV4 = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
IPV4_RE = re.compile(rf"(?<![\d.])({IPV4})(?![\d.])")
PRIVATE_IP = r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
PORT_ALT = "|".join(str(p) for p in INDUSTRIAL_PORTS)

ICS_MODULES = {"pymodbus", "pyModbusTCP", "umodbus", "c104", "pydnp3", "dnp3", "asyncua", "opcua", "snap7", "paho"}


def _is_routable_ip(value) -> bool:
    return isinstance(value, str) and bool(IPV4_RE.fullmatch(value.strip())) and value.strip() not in ("0.0.0.0", "127.0.0.1")


def _module_uses(ctx: FileContext, *modules: str) -> bool:
    return ctx.tree is not None and bool(pa.imported_modules(ctx.tree) & set(modules))


# --- OT-001 Modbus/TCP without TLS ---------------------------------------------------------

MODBUS_PLAIN = {
    "ModbusTcpClient", "AsyncModbusTcpClient", "ModbusUdpClient", "AsyncModbusUdpClient",
    "ModbusTcpServer", "StartTcpServer", "StartAsyncTcpServer", "StartUdpServer", "StartAsyncUdpServer",
}


def ot001_ast(ctx: FileContext) -> Iterator[Match]:
    for call in pa.method_calls(ctx.tree, *MODBUS_PLAIN):
        yield Match(line=call.lineno)
    # pyModbusTCP only supports plain TCP.
    if _module_uses(ctx, "pyModbusTCP"):
        for call in pa.method_calls(ctx.tree, "ModbusClient", "ModbusServer"):
            yield Match(line=call.lineno)


def ot001_text(ctx: FileContext) -> Iterator[Match]:
    yield from grep(ctx, r"\b(Async)?Modbus(Tcp|Udp)Client\b|\bStart(Async)?(Tcp|Udp)Server\b|\.connectTCP\s*\("
                         r"|client\.TCP\s*\(|NewTCPClientHandler|modbus\.TCPClient\s*\(")


OT_001 = Rule(
    id="OT-001",
    title="Modbus/TCP without TLS",
    category=CATEGORY,
    pack=PACK,
    severity_floor="HIGH",
    cwe="CWE-319",
    owasp="A02:2021",
    stride=("Spoofing", "Tampering", "Information Disclosure"),
    description="Modbus/TCP has no authentication or encryption. Anyone who can reach the port can read and "
                "write registers or coils, and traffic can be sniffed or modified in transit.",
    remediation="Use Modbus/TCP Security (TLS, port 802), e.g. `ModbusTlsClient` / `StartTlsServer` in pymodbus "
                "with mutual certificates, or tunnel the link through an authenticated VPN, and restrict who can reach "
                "the device with network segmentation.",
    references=("https://cwe.mitre.org/data/definitions/319.html", "https://pymodbus.readthedocs.io/"),
    exposure=True,
    match_ast=ot001_ast,
    match_text=ot001_text,
)


# --- OT-002 Unvalidated writes to field devices --------------------------------------------

WRITE_METHODS = {
    "write_register": "value", "write_registers": "values", "write_coil": "value", "write_coils": "values",
    "write_single_register": "value", "write_multiple_registers": "values",
    "write_single_coil": "value", "write_multiple_coils": "values",
}
VALIDATORS = re.compile(r"^(min|max|clamp|clip|validate\w*|check\w*|ensure\w*|bounded\w*|limit\w*)$", re.I)


def _literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_literal(e) for e in node.elts)
    if isinstance(node, ast.UnaryOp):
        return _literal(node.operand)
    return False


def _data_names(node: ast.AST) -> set:
    """Variable names in an expression, excluding names that are only called as functions."""
    called = {n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    return pa.names_in(node) - called


def _is_validated(scope: ast.AST, names: set, before_line: int) -> bool:
    for node in ast.walk(scope):
        if getattr(node, "lineno", before_line) > before_line:
            continue
        if isinstance(node, ast.Compare) and pa.names_in(node) & names:
            return True
        if isinstance(node, ast.Call):
            fname = pa.short_name(node)
            if VALIDATORS.match(fname) and any(pa.names_in(a) & names for a in node.args):
                return True
    return False


def ot002_ast(ctx: FileContext) -> Iterator[Match]:
    for call in pa.method_calls(ctx.tree, *WRITE_METHODS):
        value = pa.arg(call, 1, WRITE_METHODS[pa.short_name(call)])
        if value is None or _literal(value):
            continue
        names = _data_names(value)
        scope = pa.enclosing_function(ctx.tree, call) or ctx.tree
        if names and _is_validated(scope, names, call.lineno):
            continue
        detail = "The written value is not range-checked before it is sent to the device."
        yield Match(line=call.lineno, detail=detail, confidence="MEDIUM" if names else "LOW")


def ot002_text(ctx: FileContext) -> Iterator[Match]:
    pattern = re.compile(r"write_?(single_?|multiple_?)?(register|registers|coil|coils)\s*\(\s*[^,()]+,\s*[A-Za-z_]", re.I)
    for m in grep(ctx, pattern):
        yield Match(line=m.line, confidence="LOW")


OT_002 = Rule(
    id="OT-002",
    title="Unvalidated write to a field device",
    category=CATEGORY,
    pack=PACK,
    severity_floor="HIGH",
    cwe="CWE-20",
    owasp="A04:2021",
    stride=("Tampering", "Denial of Service"),
    description="A register or coil write uses a value that is not a constant and is not bounds-checked. "
                "Out-of-range setpoints can drive physical equipment into unsafe states.",
    remediation="Validate type and engineering range of every value before writing (e.g. `if not 0 <= value <= MAX: "
                "raise ValueError`), use an allow-list of writable addresses, and require operator confirmation for "
                "safety-relevant setpoints.",
    references=("https://cwe.mitre.org/data/definitions/20.html",),
    confidence="MEDIUM",
    user_input=True,
    match_ast=ot002_ast,
    match_text=ot002_text,
)


# --- OT-003 IEC 60870-5-104 / DNP3 without secure authentication ----------------------------

def ot003_ast(ctx: FileContext) -> Iterator[Match]:
    if _module_uses(ctx, "c104"):
        for call in pa.iter_calls(ctx.tree):
            if pa.call_name(call) in ("c104.Client", "c104.Server", "Client", "Server") and not pa.has_kwarg(call, "transport_security"):
                if pa.call_name(call).startswith("c104") or "c104" in pa.imported_modules(ctx.tree):
                    yield Match(line=call.lineno, detail="IEC 60870-5-104 endpoint without `transport_security` (TLS).")
    for call in pa.method_calls(ctx.tree, "AddTCPClient", "AddTCPServer"):
        yield Match(line=call.lineno, detail="DNP3 channel over plain TCP (no TLS / Secure Authentication).")


def ot003_text(ctx: FileContext) -> Iterator[Match]:
    pattern = re.compile(r"AddTCPClient|AddTCPServer|c104\.(Client|Server)\s*\(")
    for number, line in enumerate(ctx.lines, 1):
        if is_comment(line):
            continue
        if pattern.search(line) and "transport_security" not in line:
            yield Match(line=number)


OT_003 = Rule(
    id="OT-003",
    title="IEC 60870-5-104 / DNP3 without secure authentication",
    category=CATEGORY,
    pack=PACK,
    severity_floor="HIGH",
    cwe="CWE-319",
    owasp="A02:2021",
    stride=("Spoofing", "Tampering", "Information Disclosure"),
    description="Telecontrol protocols IEC 60870-5-104 and DNP3 have no built-in protection. Without TLS "
                "(IEC 62351-3) or DNP3 Secure Authentication, commands can be spoofed or replayed. "
                "Heuristic: based on library calls, not on a protocol trace.",
    remediation="Enable TLS for IEC 104 (e.g. `transport_security=` in c104) or use DNP3 over TLS / Secure "
                "Authentication v5/v6, and restrict telecontrol links to dedicated, monitored network zones.",
    references=("https://cwe.mitre.org/data/definitions/319.html",),
    confidence="MEDIUM",
    exposure=True,
    match_ast=ot003_ast,
    match_text=ot003_text,
)


# --- OT-004 OPC UA without security -------------------------------------------------------

OPCUA_INSECURE = re.compile(
    r"SecurityPolicyType\.NoSecurity|MessageSecurityMode\.None_?\b|SecurityPolicy(#|\.)None\b"
    r"|set_security_string\(\s*['\"]None|SecurityPolicies\.None\b|InsecureCertificateValidator"
    r"|AutoAcceptUntrustedCertificates\s*=\s*true|auto_accept\w*\s*=\s*True"
)


def ot004_text(ctx: FileContext) -> Iterator[Match]:
    yield from grep(ctx, OPCUA_INSECURE)


def ot004_ast(ctx: FileContext) -> Iterator[Match]:
    yield from ot004_text(ctx)
    if not _module_uses(ctx, "asyncua", "opcua"):
        return
    called = {pa.short_name(c) for c in pa.iter_calls(ctx.tree)}
    for call in pa.method_calls(ctx.tree, "Client"):
        if not called & {"set_security", "set_security_string", "load_client_certificate"}:
            yield Match(line=call.lineno, detail="No security policy is configured, so the client connects with "
                                                 "SecurityPolicy None.", severity="HIGH")
    for call in pa.method_calls(ctx.tree, "Server"):
        if "set_security_policy" not in called:
            yield Match(line=call.lineno, detail="The server keeps the default endpoints, which include "
                                                 "SecurityPolicy None.", confidence="MEDIUM")


OT_004 = Rule(
    id="OT-004",
    title="OPC UA without message security",
    category=CATEGORY,
    pack=PACK,
    severity_floor="HIGH",
    cwe="CWE-319",
    owasp="A02:2021",
    stride=("Spoofing", "Tampering", "Information Disclosure"),
    description="OPC UA is used with SecurityPolicy None / MessageSecurityMode None or without certificate "
                "validation, so sessions are neither signed nor encrypted and endpoints are not authenticated.",
    remediation="Use `Basic256Sha256` (or newer) with `SignAndEncrypt`, validate server and client certificates "
                "against a trust list, and remove the None endpoint from servers.",
    references=("https://cwe.mitre.org/data/definitions/319.html", "https://opcua-asyncio.readthedocs.io/"),
    exposure=True,
    match_ast=ot004_ast,
    match_text=ot004_text,
)


# --- OT-005 MQTT without TLS / credentials, wildcard subscriptions --------------------------

def _wildcard(topic) -> bool:
    return isinstance(topic, str) and (topic.strip() == "#" or topic.strip().endswith("/#"))


def _topics(node):
    if isinstance(node, ast.Constant):
        yield node.value
    elif isinstance(node, (ast.List, ast.Tuple)):
        for elt in node.elts:
            yield from _topics(elt.elts[0] if isinstance(elt, ast.Tuple) and elt.elts else elt)


def ot005_ast(ctx: FileContext) -> Iterator[Match]:
    tree = ctx.tree
    clients = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            name = pa.call_name(node.value)
            if name.endswith("Client") and ("mqtt" in name.lower() or _module_uses(ctx, "paho")):
                clients.update(pa.dotted_name(t) for t in node.targets)
    if not clients:
        return

    called = {pa.short_name(c) for c in pa.iter_calls(tree)}
    has_tls = bool(called & {"tls_set", "tls_set_context"})
    has_auth = "username_pw_set" in called
    consts = pa.module_constants(tree)

    for call, receiver in pa.call_receivers(tree, "connect", "connect_async"):
        if receiver not in clients:
            continue
        port = pa.resolve(pa.arg(call, 1, "port"), consts)
        problems = []
        if not has_tls or port == 1883:
            problems.append("without TLS (port 1883 / no `tls_set`)")
        if not has_auth:
            problems.append("without credentials (`username_pw_set` never called)")
        if problems:
            yield Match(line=call.lineno, detail="Broker connection " + " and ".join(problems) + ".")

    for call, receiver in pa.call_receivers(tree, "subscribe"):
        if receiver in clients and any(_wildcard(t) for t in _topics(pa.arg(call, 0, "topic"))):
            yield Match(line=call.lineno, detail="Wildcard subscription `#` receives every control topic.")


def ot005_text(ctx: FileContext) -> Iterator[Match]:
    yield from grep(ctx, r"mqtt\.connect\(\s*['\"]mqtt://|['\"]tcp://[^'\"]+:1883['\"]|subscribe\(\s*['\"](#|[^'\"]*/#)['\"]")


OT_005 = Rule(
    id="OT-005",
    title="Insecure MQTT usage",
    category=CATEGORY,
    pack=PACK,
    severity_floor="MEDIUM",
    cwe="CWE-319",
    owasp="A02:2021",
    stride=("Spoofing", "Tampering", "Information Disclosure"),
    description="MQTT is used without TLS or without client credentials, or subscribes with a `#` wildcard. "
                "Telemetry and commands can be read or injected by anyone who reaches the broker.",
    remediation="Connect on port 8883 with `tls_set()` and certificate validation, authenticate every client "
                "(`username_pw_set` or client certificates), and subscribe only to the specific topics needed with "
                "broker-side ACLs.",
    references=("https://cwe.mitre.org/data/definitions/319.html", "https://eclipse.dev/paho/files/paho.mqtt.python/html/"),
    exposure=True,
    match_ast=ot005_ast,
    match_text=ot005_text,
)


# --- OT-006 Cleartext legacy protocols ----------------------------------------------------

PRIVATE_HTTP = re.compile(rf"['\"]http://{PRIVATE_IP}")
LEGACY_TEXT = re.compile(rf"\btelnetlib\b|\bftplib\.FTP\(|\bFTP\(|new\s+Telnet\b|require\(['\"]telnet|['\"](ftp|telnet)://|['\"]http://{PRIVATE_IP}")


def ot006_ast(ctx: FileContext) -> Iterator[Match]:
    for call in pa.method_calls(ctx.tree, "Telnet"):
        yield Match(line=call.lineno, detail="Telnet sends credentials and commands in cleartext.")
    for call in pa.method_calls(ctx.tree, "FTP"):
        yield Match(line=call.lineno, detail="FTP sends credentials and files in cleartext.")
    for m in grep(ctx, PRIVATE_HTTP):
        yield Match(line=m.line, detail="Plain HTTP to a device on a private network.")


def ot006_text(ctx: FileContext) -> Iterator[Match]:
    yield from grep(ctx, LEGACY_TEXT)


OT_006 = Rule(
    id="OT-006",
    title="Cleartext legacy protocol",
    category=CATEGORY,
    pack=PACK,
    severity_floor="MEDIUM",
    cwe="CWE-319",
    owasp="A02:2021",
    stride=("Information Disclosure", "Spoofing", "Tampering"),
    description="Telnet, FTP or plain HTTP is used to talk to devices. Credentials and commands travel unencrypted.",
    remediation="Replace Telnet with SSH, FTP with SFTP/FTPS (`FTP_TLS`), and HTTP with HTTPS using verified "
                "certificates. Where devices cannot be upgraded, isolate them behind an authenticated gateway.",
    references=("https://cwe.mitre.org/data/definitions/319.html",),
    exposure=True,
    match_ast=ot006_ast,
    match_text=ot006_text,
)


# --- OT-007 Hardcoded device IPs with industrial ports -------------------------------------

def _all_args(call: ast.Call):
    yield from call.args
    for kw in call.keywords:
        yield kw.value


def ot007_ast(ctx: FileContext) -> Iterator[Match]:
    consts = pa.module_constants(ctx.tree)
    for call in pa.iter_calls(ctx.tree):
        values = []
        for node in _all_args(call):
            if isinstance(node, ast.Tuple):
                values.extend(pa.resolve(e, consts) for e in node.elts)
            else:
                values.append(pa.resolve(node, consts))
        ips = [v for v in values if _is_routable_ip(v)]
        ports = [v for v in values if isinstance(v, int) and not isinstance(v, bool) and v in INDUSTRIAL_PORTS]
        if ips and ports:
            yield Match(line=call.lineno, detail=f"Device {ips[0]} on port {ports[0]} ({INDUSTRIAL_PORTS[ports[0]]}).")
    yield from ot007_text(ctx, python=True)


def ot007_text(ctx: FileContext, python: bool = False) -> Iterator[Match]:
    port_re = re.compile(rf"(?::|port\s*[=:]\s*|,\s*)({PORT_ALT})\b")
    for number, line in enumerate(ctx.lines, 1):
        if is_comment(line):
            continue
        ip = IPV4_RE.search(line)
        port = port_re.search(line)
        if ip and port and _is_routable_ip(ip.group(1)):
            if python and not re.search(rf"['\"][a-z0-9+]*://{IPV4}:|['\"]{IPV4}:\d", line):
                continue  # the AST pass handles call arguments; text only adds host:port URLs here
            p = int(port.group(1))
            yield Match(line=number, detail=f"Device {ip.group(1)} on port {p} ({INDUSTRIAL_PORTS[p]}).")


OT_007 = Rule(
    id="OT-007",
    title="Hardcoded device address on an industrial port",
    category=CATEGORY,
    pack=PACK,
    severity_floor="LOW",
    cwe="CWE-1051",
    owasp="A05:2021",
    stride=("Information Disclosure",),
    description="A device IP address and an industrial protocol port are hardcoded in the source. This exposes the "
                "plant topology to anyone with code access and makes re-addressing or segmentation changes error-prone.",
    remediation="Move device addresses into protected configuration or an asset inventory, and make sure the "
                "endpoint is only reachable from the intended control zone.",
    references=("https://cwe.mitre.org/data/definitions/1051.html",),
    exposure=True,
    match_ast=ot007_ast,
    match_text=ot007_text,
)


# --- OT-008 Default or hardcoded device credentials ----------------------------------------

DEFAULT_USERS = {"admin", "root", "administrator", "operator", "guest", "user", "supervisor", "service", "plc"}
DEFAULT_PASSWORDS = {"", "admin", "root", "1234", "12345", "guest", "pass", "user", "0000", "plc"}
USER_KWARGS = {"username", "user", "login", "userid", "user_name"}
PASSWORD_KWARGS = {"password", "passwd", "pwd", "pass_", "secret"}
POSITIONAL_LOGIN = {"username_pw_set", "login", "set_user", "set_credentials"}


def _default_pair(user, password) -> bool:
    if not isinstance(password, str):
        return False
    if password == "":
        return True
    return isinstance(user, str) and user.lower() in DEFAULT_USERS and password.lower() in DEFAULT_PASSWORDS


def ot008_ast(ctx: FileContext) -> Iterator[Match]:
    consts = pa.module_constants(ctx.tree)
    for call in pa.iter_calls(ctx.tree):
        kws = {kw.arg: pa.resolve(kw.value, consts) for kw in call.keywords if kw.arg}
        user = next((kws[k] for k in USER_KWARGS if k in kws), None)
        password = next((kws[k] for k in PASSWORD_KWARGS if k in kws), None)
        if password is None and pa.short_name(call) in POSITIONAL_LOGIN and len(call.args) >= 2:
            user, password = pa.resolve(call.args[0], consts), pa.resolve(call.args[1], consts)
        if _default_pair(user, password):
            yield Match(line=call.lineno, detail="Default or empty credentials are used to log in to a device.")
    yield from _assignment_pairs(ctx)


def _assignment_pairs(ctx: FileContext) -> Iterator[Match]:
    consts = pa.module_constants(ctx.tree)
    user = next((v for k, v in consts.items() if k.lower() in {"username", "user", "login", "device_user", "plc_user"}), None)
    for node in getattr(ctx.tree, "body", []):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            names = [t.id.lower() for t in node.targets if isinstance(t, ast.Name)]
            if any(n in {"password", "passwd", "pwd", "device_password", "plc_password"} for n in names):
                if _default_pair(user, node.value.value):
                    yield Match(line=node.lineno, detail="Default or empty device password constant.")


def ot008_text(ctx: FileContext) -> Iterator[Match]:
    defaults = "|".join(sorted(p for p in DEFAULT_PASSWORDS if p))
    yield from grep(ctx, re.compile(
        rf"(?i)passw(?:or)?d\s*[=:]\s*['\"](?:|{defaults})['\"]|['\"](?:admin|root)['\"]\s*,\s*['\"](?:|{defaults})['\"]"
    ))


OT_008 = Rule(
    id="OT-008",
    title="Default or hardcoded device credentials",
    category=CATEGORY,
    pack=PACK,
    severity_floor="HIGH",
    cwe="CWE-1392",
    owasp="A07:2021",
    stride=("Spoofing", "Elevation of Privilege"),
    description="Factory-default (e.g. admin/admin) or empty credentials are used. These are publicly documented "
                "and are the first thing an attacker tries against field devices and gateways.",
    remediation="Change default accounts on every device, use unique per-device credentials from a secret store, "
                "and disable unused accounts and services.",
    references=("https://cwe.mitre.org/data/definitions/1392.html",),
    match_ast=ot008_ast,
    match_text=ot008_text,
)


# --- OT-009 Disabled certificate verification ---------------------------------------------

TLS_OFF_TEXT = re.compile(
    r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False|_create_unverified_context|tls_insecure_set\(\s*True"
    r"|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\]?\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true"
    r"|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy|CURLOPT_SSL_VERIFYPEER\s*,\s*0"
)


def ot009_ast(ctx: FileContext) -> Iterator[Match]:
    tree = ctx.tree
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in ("verify", "check_hostname") and pa.const_value(kw.value) is False:
                    yield Match(line=node.lineno)
            name = pa.short_name(node)
            if name == "_create_unverified_context" or (name == "tls_insecure_set" and pa.const_value(pa.arg(node, 0)) is True):
                yield Match(line=node.lineno)
        elif isinstance(node, ast.Attribute) and node.attr == "CERT_NONE":
            yield Match(line=node.lineno)
        elif isinstance(node, ast.Assign) and pa.const_value(node.value) is False:
            if any(isinstance(t, ast.Attribute) and t.attr == "check_hostname" for t in node.targets):
                yield Match(line=node.lineno)


def ot009_text(ctx: FileContext) -> Iterator[Match]:
    yield from grep(ctx, TLS_OFF_TEXT)


OT_009 = Rule(
    id="OT-009",
    title="TLS certificate verification disabled",
    category=CATEGORY,
    pack=PACK,
    severity_floor="HIGH",
    cwe="CWE-295",
    owasp="A02:2021",
    stride=("Spoofing", "Tampering", "Information Disclosure"),
    description="Certificate or hostname verification is turned off, so any machine in the path can impersonate "
                "the server and read or alter the traffic despite TLS.",
    remediation="Keep verification on. For private PKIs, pin or trust the issuing CA explicitly (e.g. "
                "`verify='/path/ca.pem'`, `ssl.create_default_context(cafile=...)`).",
    references=("https://cwe.mitre.org/data/definitions/295.html",),
    exposure=True,
    match_ast=ot009_ast,
    match_text=ot009_text,
)


# --- OT-010 Missing timeouts on field-device connections -----------------------------------

# Positional index of the timeout argument, where the constructor accepts one positionally.
FIELD_CLIENTS = {
    "ModbusTcpClient": None, "AsyncModbusTcpClient": None, "ModbusTlsClient": None, "AsyncModbusTlsClient": None,
    "ModbusSerialClient": None, "AsyncModbusSerialClient": None, "ModbusUdpClient": None,
    "Telnet": 2, "FTP": 4, "FTP_TLS": None,
}
TIMEOUT_KWARGS = ("timeout", "timeout_ms", "timeout_s", "timeout_sec", "request_timeout", "connect_timeout")


def _has_timeout(call: ast.Call, positional) -> bool:
    if pa.has_kwarg(call, *TIMEOUT_KWARGS):
        return True
    return positional is not None and len(call.args) > positional


def ot010_ast(ctx: FileContext) -> Iterator[Match]:
    tree = ctx.tree
    consts = pa.module_constants(tree)
    for call in pa.method_calls(tree, *FIELD_CLIENTS):
        name = pa.import_aliases(tree).get(pa.short_name(call), pa.short_name(call))
        if not _has_timeout(call, FIELD_CLIENTS[name]):
            confidence = "MEDIUM" if "Modbus" in name else "HIGH"
            yield Match(line=call.lineno, confidence=confidence, detail=f"`{name}` is created without an explicit timeout.")
    if _module_uses(ctx, "asyncua", "opcua"):
        for call in pa.method_calls(tree, "Client"):
            if not _has_timeout(call, 1):
                yield Match(line=call.lineno, confidence="MEDIUM", detail="OPC UA client without an explicit timeout.")
    for call in pa.method_calls(tree, "create_connection"):
        address = pa.arg(call, 0, "address")
        port = pa.resolve(address.elts[1], consts) if isinstance(address, ast.Tuple) and len(address.elts) == 2 else None
        if port in INDUSTRIAL_PORTS and not _has_timeout(call, 1):
            yield Match(line=call.lineno, detail=f"Socket to port {port} ({INDUSTRIAL_PORTS[port]}) blocks without a timeout.")


OT_010 = Rule(
    id="OT-010",
    title="Field-device connection without timeout",
    category=CATEGORY,
    pack=PACK,
    severity_floor="MEDIUM",
    cwe="CWE-1088",
    owasp="A04:2021",
    stride=("Denial of Service",),
    description="A connection to a field device is opened without an explicit timeout or retry limit. "
                "A slow or unresponsive device can block the control loop indefinitely.",
    remediation="Set explicit connect/read timeouts and bounded retries with back-off, and make the control logic "
                "fail safe when a device does not answer in time.",
    references=("https://cwe.mitre.org/data/definitions/1088.html",),
    match_ast=ot010_ast,
)


RULES = (OT_001, OT_002, OT_003, OT_004, OT_005, OT_006, OT_007, OT_008, OT_009, OT_010)


def is_ot_file(ctx: FileContext) -> bool:
    """True when the file talks to industrial protocols (used for the OT impact uplift)."""
    if ctx.tree is not None and pa.imported_modules(ctx.tree) & ICS_MODULES:
        return True
    return bool(re.search(r"(?i)modbus|iec\s*-?\s*104|dnp3|opc\.tcp://|mqtt|scada|plc\b|substation", ctx.text))
