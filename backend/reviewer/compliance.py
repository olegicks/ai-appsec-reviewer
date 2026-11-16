"""Curated, static mapping of findings to IEC 62443-3-3 foundational requirements and ISO/IEC 27001:2022
Annex A technological controls.

This is an INDICATIVE mapping to help prioritise and document findings. It is not a certification or
audit result, and it is never produced or changed by the LLM.
"""
from typing import Dict, Iterable, List, Tuple

from .findings import Finding

DISCLAIMER = "Indicative mapping, not a certification or audit result."

IEC_62443_FR = {
    "FR1": "Identification and authentication control",
    "FR2": "Use control",
    "FR3": "System integrity",
    "FR4": "Data confidentiality",
    "FR5": "Restricted data flow",
    "FR6": "Timely response to events",
    "FR7": "Resource availability",
}

ISO_27001 = {
    "A.8.2": "Privileged access rights",
    "A.8.3": "Information access restriction",
    "A.8.5": "Secure authentication",
    "A.8.6": "Capacity management",
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.12": "Data leakage prevention",
    "A.8.15": "Logging",
    "A.8.16": "Monitoring activities",
    "A.8.20": "Networks security",
    "A.8.22": "Segregation of networks",
    "A.8.24": "Use of cryptography",
    "A.8.28": "Secure coding",
}

Mapping = Tuple[Tuple[str, ...], Tuple[str, ...]]  # (IEC 62443 FRs, ISO 27001 controls)

RULE_MAP: Dict[str, Mapping] = {
    "OT-001": (("FR1", "FR3", "FR4", "FR5"), ("A.8.5", "A.8.20", "A.8.24")),
    "OT-002": (("FR2", "FR3"), ("A.8.28",)),
    "OT-003": (("FR1", "FR3", "FR4", "FR5"), ("A.8.5", "A.8.20", "A.8.24")),
    "OT-004": (("FR1", "FR3", "FR4"), ("A.8.5", "A.8.24")),
    "OT-005": (("FR1", "FR4", "FR5"), ("A.8.5", "A.8.20", "A.8.24")),
    "OT-006": (("FR1", "FR4"), ("A.8.20", "A.8.24")),
    "OT-007": (("FR5",), ("A.8.9", "A.8.22")),
    "OT-008": (("FR1",), ("A.8.5",)),
    "OT-009": (("FR1", "FR3", "FR4"), ("A.8.24",)),
    "OT-010": (("FR7",), ("A.8.6",)),
}

_AUTH: Mapping = (("FR1",), ("A.8.5",))
_SECRETS: Mapping = (("FR1", "FR4"), ("A.8.5", "A.8.12"))
_PRIV: Mapping = (("FR2",), ("A.8.2",))
_ACCESS: Mapping = (("FR2",), ("A.8.3",))
_CODE: Mapping = (("FR3",), ("A.8.28",))
_SUPPLY: Mapping = (("FR3",), ("A.8.8",))
_INTEGRITY_CFG: Mapping = (("FR3",), ("A.8.9",))
_CRYPTO: Mapping = (("FR3", "FR4"), ("A.8.24",))
_CLEARTEXT: Mapping = (("FR3", "FR4"), ("A.8.20", "A.8.24"))
_LEAK: Mapping = (("FR4",), ("A.8.12",))
_NETWORK: Mapping = (("FR5",), ("A.8.20", "A.8.22"))
_EVENTS: Mapping = (("FR6",), ("A.8.15", "A.8.16"))
_HEALTH: Mapping = (("FR6", "FR7"), ("A.8.16",))
_CAPACITY: Mapping = (("FR7",), ("A.8.6",))

CWE_MAP: Dict[str, Mapping] = {
    **{f"CWE-{c}": _AUTH for c in (287, 306, 1392, 384, 521)},
    **{f"CWE-{c}": _SECRETS for c in (798, 259, 321)},
    **{f"CWE-{c}": _PRIV for c in (250, 269, 732)},
    **{f"CWE-{c}": _ACCESS for c in (22, 862, 863)},
    **{f"CWE-{c}": _CODE for c in (20, 77, 78, 79, 89, 94, 120, 121, 125, 190, 416, 434, 502, 601, 611, 787, 918, 352)},
    **{f"CWE-{c}": _SUPPLY for c in (1104, 1395)},
    **{f"CWE-{c}": _INTEGRITY_CFG for c in (494, 1357)},
    **{f"CWE-{c}": _CRYPTO for c in (295, 327, 328, 330, 916)},
    "CWE-319": _CLEARTEXT,
    **{f"CWE-{c}": _LEAK for c in (200, 209, 532)},
    **{f"CWE-{c}": _NETWORK for c in (668, 1051)},
    **{f"CWE-{c}": _EVENTS for c in (117, 223, 778)},
    "CWE-703": _HEALTH,
    **{f"CWE-{c}": _CAPACITY for c in (400, 770, 1088)},
}

STRIDE_MAP: Dict[str, Mapping] = {
    "Spoofing": _AUTH,
    "Tampering": _CODE,
    "Repudiation": _EVENTS,
    "Information Disclosure": _LEAK,
    "Denial of Service": _CAPACITY,
    "Elevation of Privilege": _PRIV,
}


def controls_for(f: Finding) -> Dict[str, List[str]]:
    """Rule-specific mapping first, then by CWE, then by STRIDE category."""
    fr, iso = RULE_MAP.get(f.rule_id) or CWE_MAP.get(f.cwe) or ((), ())
    fr, iso = set(fr), set(iso)
    if not fr:
        for category in f.stride:
            extra_fr, extra_iso = STRIDE_MAP.get(category, ((), ()))
            fr.update(extra_fr)
            iso.update(extra_iso)
    if f.category == "config":
        iso.add("A.8.9")
    if f.category == "dependency":
        iso.add("A.8.8")
    return {
        "iec62443": sorted(fr, key=lambda c: list(IEC_62443_FR).index(c)),
        "iso27001": sorted(iso, key=lambda c: list(ISO_27001).index(c)),
    }


def summary(findings: Iterable[Finding], mapping: Dict[str, Dict[str, List[str]]]) -> Dict:
    linked_fr: Dict[str, List[str]] = {k: [] for k in IEC_62443_FR}
    linked_iso: Dict[str, List[str]] = {k: [] for k in ISO_27001}
    for f in findings:
        for fr in mapping[f.fingerprint]["iec62443"]:
            linked_fr[fr].append(f.fingerprint)
        for ctrl in mapping[f.fingerprint]["iso27001"]:
            linked_iso[ctrl].append(f.fingerprint)
    return {
        "disclaimer": DISCLAIMER,
        "iec62443": [{"id": k, "title": IEC_62443_FR[k], "findings": v} for k, v in linked_fr.items()],
        "iso27001": [{"id": k, "title": ISO_27001[k], "findings": v} for k, v in linked_iso.items()],
    }
