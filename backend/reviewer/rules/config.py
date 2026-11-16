"""Container and deployment configuration rules: Dockerfile, docker-compose and Kubernetes manifests."""
import os
import re
from typing import Dict, Iterator, List, Optional, Tuple

import yaml

from .base import FileContext, Match, Rule

PACK = "config"
CATEGORY = "config"

DOCKERFILE, COMPOSE, K8S = "DOCKERFILE", "COMPOSE", "K8S"
REQUIREMENTS, PYPROJECT, PACKAGE_JSON = "REQUIREMENTS", "PYPROJECT", "PACKAGE_JSON"
CONFIG_KINDS = (DOCKERFILE, COMPOSE, K8S)
MANIFEST_KINDS = (REQUIREMENTS, PYPROJECT, PACKAGE_JSON)

SECRET_NAME = re.compile(r"(?i)(passw(or)?d|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)")
SENSITIVE_PORTS = {
    5432: "PostgreSQL", 3306: "MySQL", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
    5601: "Kibana", 11211: "Memcached", 5984: "CouchDB", 8086: "InfluxDB", 15672: "RabbitMQ admin",
    2375: "Docker API", 9000: "admin console", 8080: "admin console", 502: "Modbus/TCP", 1883: "MQTT", 4840: "OPC UA",
}
WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


# --- detection -----------------------------------------------------------------------------

def detect_kind(path: str, text: str) -> Optional[str]:
    """Classify a config or manifest file by name, then by content (used for pasted snippets)."""
    name = os.path.basename(path).lower()
    if name.startswith("dockerfile") or name.endswith(".dockerfile") or name == "containerfile":
        return DOCKERFILE
    if re.fullmatch(r"(docker-)?compose[\w.-]*\.ya?ml", name):
        return COMPOSE
    if re.fullmatch(r"requirements[\w.-]*\.txt", name):
        return REQUIREMENTS
    if name == "pyproject.toml":
        return PYPROJECT
    if name == "package.json":
        return PACKAGE_JSON
    if name.endswith((".yaml", ".yml")):
        return K8S if _looks_like_k8s(text) else None
    if name.startswith("snippet"):
        return detect_from_content(text)
    return None


def _looks_like_k8s(text: str) -> bool:
    return bool(re.search(r"(?m)^apiVersion:\s*\S+", text) and re.search(r"(?m)^kind:\s*\S+", text))


def detect_from_content(text: str) -> Optional[str]:
    stripped = text.strip()
    if re.search(r"(?mi)^\s*FROM\s+\S+", text) and re.search(r"(?mi)^\s*(RUN|CMD|ENTRYPOINT|COPY|ADD|USER|ENV)\b", text):
        return DOCKERFILE
    if re.search(r"(?m)^services:\s*$", text):
        return COMPOSE
    if _looks_like_k8s(text):
        return K8S
    if stripped.startswith("{") and '"dependencies"' in text:
        return PACKAGE_JSON
    if re.search(r"(?m)^\[(project|tool\.poetry)\]", text):
        return PYPROJECT
    if re.search(r"(?m)^\s*[A-Za-z0-9_.\-\[\]]+\s*(==|>=|~=|<=)\s*[\w.*]+", text):
        return REQUIREMENTS
    return None


# --- Dockerfile ------------------------------------------------------------------------------

def dockerfile_instructions(text: str) -> List[Tuple[int, str, str]]:
    """(line, INSTRUCTION, arguments) with line continuations joined."""
    out, buffer, start = [], "", 0
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not buffer and (not line or line.startswith("#")):
            continue
        if not buffer:
            start = number
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        buffer += line
        parts = buffer.split(None, 1)
        out.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buffer = ""
    return out


def _image_tag_problem(image: str, aliases: set) -> Optional[str]:
    image = image.strip()
    if not image or image.lower() == "scratch" or image in aliases or "@sha256:" in image or image.startswith("$"):
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return f"`{image}` has no tag, so it resolves to `latest`."
    if last.endswith(":latest"):
        return f"`{image}` uses the mutable `latest` tag."
    return None


def docker001(ctx: FileContext) -> Iterator[Match]:
    instructions = dockerfile_instructions(ctx.text)
    froms = [i for i in instructions if i[1] == "FROM"]
    if not froms:
        return
    final_stage = froms[-1][0]
    users = [i for i in instructions if i[1] == "USER" and i[0] > final_stage]
    if not users:
        yield Match(line=final_stage, detail="The final stage never switches to a non-root USER.")
    elif users[-1][2].split(":")[0].strip() in ("root", "0"):
        yield Match(line=users[-1][0], detail="The final USER is root.")


def docker002(ctx: FileContext) -> Iterator[Match]:
    aliases = set()
    for line, instr, args in dockerfile_instructions(ctx.text):
        if instr != "FROM":
            continue
        tokens = [t for t in args.split() if not t.startswith("--")]
        if not tokens:
            continue
        problem = _image_tag_problem(tokens[0], aliases)
        if len(tokens) >= 3 and tokens[1].lower() == "as":
            aliases.add(tokens[2])
        if problem:
            yield Match(line=line, detail=problem)


def docker003(ctx: FileContext) -> Iterator[Match]:
    for line, instr, args in dockerfile_instructions(ctx.text):
        if instr == "ADD" and re.search(r"\bhttps?://", args):
            yield Match(line=line)


def docker004(ctx: FileContext) -> Iterator[Match]:
    for line, instr, args in dockerfile_instructions(ctx.text):
        if instr not in ("ENV", "ARG"):
            continue
        for name, value in _assignments(args, instr):
            if SECRET_NAME.search(name):
                if value:
                    yield Match(line=line, detail=f"`{name}` is baked into the image layers.")
                elif instr == "ARG":
                    yield Match(line=line, severity="MEDIUM", confidence="MEDIUM",
                                detail=f"Build argument `{name}` is recorded in the image history.")


def _assignments(args: str, instr: str) -> List[Tuple[str, str]]:
    """`ENV A=1 B=2`, `ARG NAME=default`, `ARG NAME` and legacy `ENV NAME value`."""
    tokens = args.split()
    if not tokens:
        return []
    if "=" in tokens[0]:
        return [(k, v.strip("\"'")) for k, _, v in (t.partition("=") for t in tokens if "=" in t)]
    return [(tokens[0], " ".join(tokens[1:]).strip("\"'") if instr == "ENV" else "")]


def docker005(ctx: FileContext) -> Iterator[Match]:
    for line, instr, args in dockerfile_instructions(ctx.text):
        if instr == "RUN" and re.search(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", args):
            yield Match(line=line)


# --- YAML helpers ----------------------------------------------------------------------------

def yaml_docs(text: str) -> List[yaml.Node]:
    try:
        return [d for d in yaml.compose_all(text, Loader=yaml.SafeLoader) if d is not None]
    except yaml.YAMLError:
        return []


def ymap(node) -> Dict[str, Tuple[yaml.Node, yaml.Node]]:
    if not isinstance(node, yaml.MappingNode):
        return {}
    return {k.value: (k, v) for k, v in node.value if isinstance(k, yaml.ScalarNode)}


def yget(node, *path):
    """Value node at `path` (keys), or None."""
    for key in path:
        node = ymap(node).get(key, (None, None))[1]
        if node is None:
            return None
    return node


def yscalar(node) -> Optional[str]:
    return node.value if isinstance(node, yaml.ScalarNode) else None


def ytrue(node) -> bool:
    return (yscalar(node) or "").lower() in ("true", "yes", "on")


def yline(node) -> int:
    return node.start_mark.line + 1


def yseq(node) -> list:
    return node.value if isinstance(node, yaml.SequenceNode) else []


# --- docker-compose -------------------------------------------------------------------------

def compose_services(ctx: FileContext):
    for doc in yaml_docs(ctx.text):
        for name, (key, service) in ymap(yget(doc, "services")).items():
            yield name, key, service


def compose001(ctx):
    for name, _key, svc in compose_services(ctx):
        node = yget(svc, "privileged")
        if node is not None and ytrue(node):
            yield Match(line=yline(node), detail=f"Service `{name}` runs privileged.")


def compose002(ctx):
    for name, _key, svc in compose_services(ctx):
        node = yget(svc, "network_mode")
        if yscalar(node) == "host":
            yield Match(line=yline(node), detail=f"Service `{name}` shares the host network stack.")


def _published_port(entry) -> Tuple[Optional[str], Optional[int], int]:
    """(host_ip, target_port, line) for short and long port syntax."""
    if isinstance(entry, yaml.ScalarNode):
        parts = entry.value.split("/")[0].split(":")
        if len(parts) == 1:
            return None, None, yline(entry)  # container-only port, not published
        host_ip = parts[0] if len(parts) == 3 else ""
        target = parts[-1].split("-")[0]
        return host_ip, int(target) if target.isdigit() else None, yline(entry)
    target = yscalar(yget(entry, "target"))
    host_ip = yscalar(yget(entry, "host_ip")) or ""
    published = yget(entry, "published")
    if published is None:
        return None, None, yline(entry)
    return host_ip, int(target) if target and target.isdigit() else None, yline(entry)


def compose003(ctx):
    for name, _key, svc in compose_services(ctx):
        for entry in yseq(yget(svc, "ports")):
            host_ip, target, line = _published_port(entry)
            if host_ip is None or target not in SENSITIVE_PORTS:
                continue
            if host_ip in ("", "0.0.0.0", "::", "[::]"):
                yield Match(line=line, detail=f"`{name}` publishes {SENSITIVE_PORTS[target]} (port {target}) on all interfaces.")


def compose004(ctx):
    for name, _key, svc in compose_services(ctx):
        for entry in yseq(yget(svc, "volumes")):
            source = yscalar(entry) or yscalar(yget(entry, "source")) or ""
            if "docker.sock" in source:
                yield Match(line=yline(entry), detail=f"Service `{name}` mounts the Docker socket.")


def compose005(ctx):
    for name, key, svc in compose_services(ctx):
        missing = [k for k in ("restart", "healthcheck") if yget(svc, k) is None]
        if missing:
            yield Match(line=yline(key), detail=f"Service `{name}` has no {' or '.join(missing)}.")


# --- Kubernetes -----------------------------------------------------------------------------

def pod_specs(ctx: FileContext):
    for doc in yaml_docs(ctx.text):
        kind = yscalar(yget(doc, "kind"))
        if kind not in WORKLOAD_KINDS:
            continue
        if kind == "Pod":
            spec = yget(doc, "spec")
        elif kind == "CronJob":
            spec = yget(doc, "spec", "jobTemplate", "spec", "template", "spec")
        else:
            spec = yget(doc, "spec", "template", "spec")
        if spec is not None:
            name = yscalar(yget(doc, "metadata", "name")) or kind
            yield name, doc, spec


def containers(spec):
    for key in ("containers", "initContainers"):
        for c in yseq(yget(spec, key)):
            yield yscalar(yget(c, "name")) or "container", c


def k8s001(ctx):
    for _w, _doc, spec in pod_specs(ctx):
        for name, c in containers(spec):
            node = yget(c, "securityContext", "privileged")
            if node is not None and ytrue(node):
                yield Match(line=yline(node), detail=f"Container `{name}` is privileged.")


def k8s002(ctx):
    for _w, _doc, spec in pod_specs(ctx):
        pod_level = yget(spec, "securityContext", "runAsNonRoot")
        for name, c in containers(spec):
            node = yget(c, "securityContext", "runAsNonRoot") or pod_level
            if node is None:
                yield Match(line=yline(c), detail=f"Container `{name}` does not set runAsNonRoot.")
            elif not ytrue(node):
                yield Match(line=yline(node), detail=f"Container `{name}` sets runAsNonRoot: false.")


def k8s003(ctx):
    for _w, _doc, spec in pod_specs(ctx):
        for name, c in containers(spec):
            node = yget(c, "securityContext", "allowPrivilegeEscalation")
            if node is not None and ytrue(node):
                yield Match(line=yline(node), detail=f"Container `{name}` allows privilege escalation.")


def k8s004(ctx):
    for workload, _doc, spec in pod_specs(ctx):
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            node = yget(spec, key)
            if node is not None and ytrue(node):
                yield Match(line=yline(node), detail=f"`{workload}` sets {key}: true.")


def k8s005(ctx):
    for _w, _doc, spec in pod_specs(ctx):
        for name, c in containers(spec):
            limits = yget(c, "resources", "limits")
            missing = [k for k in ("cpu", "memory") if yget(limits, k) is None] if limits is not None else ["cpu", "memory"]
            if missing:
                yield Match(line=yline(c), detail=f"Container `{name}` has no {' / '.join(missing)} limit.")


def k8s006(ctx):
    for _w, _doc, spec in pod_specs(ctx):
        for _name, c in containers(spec):
            node = yget(c, "image")
            problem = _image_tag_problem(yscalar(node) or "", set()) if node is not None else None
            if problem:
                yield Match(line=yline(node), detail=problem)


def _rule(id, title, kind, severity, cwe, owasp, stride, description, remediation, fn, **kw) -> Rule:
    return Rule(
        id=id, title=title, category=CATEGORY, pack=PACK, severity_floor=severity, cwe=cwe, owasp=owasp,
        stride=stride, description=description, remediation=remediation, languages=(kind,),
        references=(f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html",), match_config=fn, **kw,
    )


RULES = (
    _rule("DOCKER-001", "Container runs as root", DOCKERFILE, "MEDIUM", "CWE-250", "A05:2021", ("Elevation of Privilege",),
          "The image runs its process as root. A compromise of the application gives root inside the container, "
          "which makes container escapes and host damage much easier.",
          "Create an unprivileged user and add `USER app` (or a numeric UID) in the final stage.", docker001),
    _rule("DOCKER-002", "Unpinned base image", DOCKERFILE, "LOW", "CWE-1357", "A06:2021", ("Tampering",),
          "The base image is not pinned to a version, so builds silently pick up new, untested or compromised "
          "upstream content.",
          "Pin a specific version tag, ideally with a digest (`image:1.2.3@sha256:...`), and update it deliberately.",
          docker002),
    _rule("DOCKER-003", "ADD from a remote URL", DOCKERFILE, "MEDIUM", "CWE-494", "A08:2021", ("Tampering",),
          "`ADD <url>` downloads content at build time without integrity verification.",
          "Download with `curl` plus a checksum (`sha256sum -c`) or use `ADD --checksum=...`, and prefer `COPY` for "
          "local files.", docker003),
    _rule("DOCKER-004", "Secret in ENV or ARG", DOCKERFILE, "HIGH", "CWE-798", "A07:2021",
          ("Information Disclosure", "Spoofing"),
          "A credential is set through ENV or ARG. Both end up in the image metadata or history, readable by anyone "
          "who can pull the image.",
          "Use BuildKit secrets (`RUN --mount=type=secret`) at build time and inject runtime secrets from the "
          "orchestrator's secret store.", docker004),
    _rule("DOCKER-005", "Remote script piped to a shell", DOCKERFILE, "HIGH", "CWE-494", "A08:2021", ("Tampering",),
          "A script is downloaded and executed in one step (`curl ... | sh`) without any integrity check.",
          "Download to a file, verify a pinned checksum or signature, then execute it; better, use a versioned package.",
          docker005),
    _rule("COMPOSE-001", "Privileged service", COMPOSE, "HIGH", "CWE-250", "A05:2021", ("Elevation of Privilege",),
          "`privileged: true` gives the container almost all host capabilities and device access.",
          "Remove `privileged` and grant only the specific capabilities (`cap_add`) or devices that are needed.",
          compose001),
    _rule("COMPOSE-002", "Host network mode", COMPOSE, "MEDIUM", "CWE-668", "A05:2021",
          ("Information Disclosure", "Elevation of Privilege"),
          "`network_mode: host` removes network isolation; every port the service opens is exposed on the host.",
          "Use a dedicated bridge network and publish only the ports that are required.", compose002),
    _rule("COMPOSE-003", "Sensitive port published on all interfaces", COMPOSE, "MEDIUM", "CWE-668", "A05:2021",
          ("Information Disclosure", "Elevation of Privilege"),
          "A database, broker or admin interface is published without a host IP, which binds it to 0.0.0.0.",
          "Bind to localhost (`127.0.0.1:5432:5432`) or keep the service on an internal network without published ports.",
          compose003, exposure=True),
    _rule("COMPOSE-004", "Docker socket mounted", COMPOSE, "HIGH", "CWE-250", "A05:2021", ("Elevation of Privilege",),
          "Mounting `/var/run/docker.sock` lets the container control the Docker daemon, which equals root on the host.",
          "Do not mount the socket; if container management is required, use a restricted socket proxy.", compose004),
    _rule("COMPOSE-005", "Missing restart policy or healthcheck", COMPOSE, "LOW", "CWE-703", "A05:2021",
          ("Denial of Service",),
          "Without a restart policy and healthcheck, a crashed or hung service is not detected or recovered.",
          "Add `restart: unless-stopped` and a `healthcheck` that probes the service.", compose005),
    _rule("K8S-001", "Privileged container", K8S, "HIGH", "CWE-250", "A05:2021", ("Elevation of Privilege",),
          "`securityContext.privileged: true` disables most container isolation.",
          "Remove `privileged` and add only the specific capabilities that are needed.", k8s001),
    _rule("K8S-002", "Container may run as root", K8S, "MEDIUM", "CWE-250", "A05:2021", ("Elevation of Privilege",),
          "`runAsNonRoot` is missing or false, so the container can run as UID 0.",
          "Set `securityContext.runAsNonRoot: true` and a non-zero `runAsUser` at pod or container level.", k8s002),
    _rule("K8S-003", "Privilege escalation allowed", K8S, "MEDIUM", "CWE-269", "A05:2021", ("Elevation of Privilege",),
          "`allowPrivilegeEscalation: true` lets processes gain more privileges than their parent (e.g. via setuid).",
          "Set `allowPrivilegeEscalation: false` and drop all capabilities.", k8s003),
    _rule("K8S-004", "Host namespace shared", K8S, "HIGH", "CWE-668", "A05:2021",
          ("Information Disclosure", "Elevation of Privilege"),
          "The pod shares the host's network, PID or IPC namespace and can observe or interfere with host processes.",
          "Remove `hostNetwork`, `hostPID` and `hostIPC` unless strictly required and documented.", k8s004),
    _rule("K8S-005", "Missing resource limits", K8S, "LOW", "CWE-770", "A04:2021", ("Denial of Service",),
          "Without CPU and memory limits a single container can starve the node.",
          "Set `resources.limits.cpu` and `resources.limits.memory` (and matching requests).", k8s005),
    _rule("K8S-006", "Unpinned container image", K8S, "LOW", "CWE-1357", "A06:2021", ("Tampering",),
          "The image uses `latest` or no tag, so deployments are not reproducible and may pull unreviewed content.",
          "Pin a version tag and, ideally, a digest.", k8s006),
)
