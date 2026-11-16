"""OSV.dev lookup for vulnerable direct dependencies.

Batch query first (returns only ids), then details for a capped number of unique ids. Every network
problem degrades to status "unavailable"; the scan itself always completes.
"""
import logging
import time
from typing import Dict, List, Optional, Tuple

import httpx

from .config import settings
from .findings import Finding
from .rules.deps import Dependency

logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1"
OSV_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def _make_client() -> httpx.Client:
    return httpx.Client(timeout=settings.osv_timeout, headers={"User-Agent": "ai-appsec-reviewer"})


def _fixed_version(vuln: dict, dep: Dependency) -> str:
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != dep.name.lower() or pkg.get("ecosystem") != dep.ecosystem:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def _severity(vuln: dict) -> str:
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    return OSV_SEVERITY.get(label, "MEDIUM")


def _finding(dep: Dependency, vuln: dict) -> Finding:
    vuln_id = vuln.get("id", "OSV")
    aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
    summary = (vuln.get("summary") or vuln.get("details") or "").strip().split("\n")[0][:300]
    fixed = _fixed_version(vuln, dep)
    range_note = "" if dep.exact else " The manifest declares a version range; the lowest allowed version was checked."
    return Finding(
        rule_id="DEP-001",
        title=f"Vulnerable dependency {dep.name} {dep.version} ({vuln_id})",
        category="dependency",
        engine="deps",
        severity=_severity(vuln),
        confidence="HIGH" if dep.exact else "LOW",
        file=dep.file,
        line=dep.line,
        snippet=f"{dep.name} {dep.version}",
        cwe="CWE-1395",
        stride=["Tampering", "Elevation of Privilege"],
        description=f"{summary or 'Known vulnerability.'}{range_note}",
        remediation=f"Upgrade {dep.name} to {fixed} or later." if fixed else f"Upgrade or replace {dep.name}; no fixed version is listed yet.",
        references=[f"https://osv.dev/vulnerability/{vuln_id}"],
        owasp="A06:2021",
        pack="deps",
        extra={"dependency": {
            "package": dep.name, "version": dep.version, "ecosystem": dep.ecosystem, "vuln_id": vuln_id,
            "aliases": aliases, "summary": summary, "fixed_version": fixed, "exact_version": dep.exact,
        }},
    )


def lookup(deps: List[Dependency], client: Optional[httpx.Client] = None) -> Tuple[List[Finding], Dict]:
    status = {"status": "ok", "source": "OSV.dev", "checked": 0, "vulnerable": 0, "note": ""}
    if not deps:
        return [], {**status, "status": "not_applicable", "note": "No dependency manifests found."}
    if not settings.osv_enabled:
        return [], {**status, "status": "disabled", "note": "Dependency check disabled on this server."}

    unique: Dict[str, Dependency] = {}
    for d in deps:
        unique.setdefault(d.key, d)
    queried = list(unique.values())[: settings.osv_max_packages]
    status["checked"] = len(queried)
    if len(unique) > len(queried):
        status["note"] = f"Only the first {len(queried)} packages were checked."

    own_client = client is None
    client = client or _make_client()
    deadline = time.monotonic() + settings.osv_budget
    try:
        batch = client.post(f"{OSV_API}/querybatch", json={"queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in queried
        ]})
        batch.raise_for_status()
        results = batch.json().get("results", [])

        hits: List[Tuple[Dependency, str]] = []
        for dep, result in zip(queried, results):
            for vuln in (result or {}).get("vulns", []) or []:
                hits.append((dep, vuln["id"]))

        details: Dict[str, dict] = {}
        for vuln_id in dict.fromkeys(v for _, v in hits):
            if len(details) >= settings.osv_max_vulns or time.monotonic() > deadline:
                status["note"] = (status["note"] + " Some vulnerability details were skipped (size/time limit).").strip()
                break
            resp = client.get(f"{OSV_API}/vulns/{vuln_id}")
            details[vuln_id] = resp.json() if resp.status_code == 200 else {"id": vuln_id}
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.warning("OSV lookup failed: %s", type(exc).__name__)
        return [], {**status, "status": "unavailable", "checked": 0,
                    "note": "Dependency check unavailable: OSV.dev could not be reached."}
    finally:
        if own_client:
            client.close()

    findings = [_finding(dep, details.get(vuln_id, {"id": vuln_id})) for dep, vuln_id in hits]
    status["vulnerable"] = len({f.extra["dependency"]["package"] for f in findings})
    return findings, status
