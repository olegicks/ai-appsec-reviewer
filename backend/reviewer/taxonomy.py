"""Static CWE lookup tables: STRIDE categories, OWASP Top 10 (2021) and a default severity.

These are curated in code on purpose: the LLM never decides threat class, OWASP category or the
severity used for risk scoring.
"""
from typing import Dict, List, Tuple

_S, _T, _R, _I, _D, _E = (
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege",
)

CWE_STRIDE: Dict[int, Tuple[str, ...]] = {
    20: (_T,), 22: (_I, _T), 77: (_T, _E), 78: (_T, _E), 79: (_T, _I), 89: (_T, _I), 94: (_T, _E),
    117: (_R, _T), 120: (_T, _D, _E), 121: (_T, _D, _E), 125: (_I, _D), 190: (_T, _D), 200: (_I,), 209: (_I,),
    223: (_R,), 250: (_E,), 259: (_S, _I, _E), 269: (_E,), 287: (_S,), 295: (_S, _T, _I), 306: (_S, _E),
    319: (_I, _T), 321: (_I,), 327: (_I,), 328: (_I,), 330: (_S,), 352: (_S, _T), 400: (_D,), 416: (_T, _E),
    434: (_T, _E), 494: (_T,), 502: (_T, _E), 532: (_I,), 601: (_S,), 611: (_I,), 668: (_I, _E), 703: (_D,),
    732: (_E, _I), 770: (_D,), 778: (_R,), 787: (_T, _D, _E), 798: (_S, _I, _E), 862: (_E,), 863: (_E,),
    916: (_I,), 918: (_I, _S), 1051: (_I,), 1088: (_D,), 1104: (_T, _E), 1357: (_T,), 1392: (_S, _E),
    1395: (_T, _E),
}

CWE_OWASP: Dict[int, str] = {
    22: "A01:2021", 200: "A01:2021", 250: "A01:2021", 269: "A01:2021", 352: "A01:2021", 601: "A01:2021",
    668: "A01:2021", 732: "A01:2021", 862: "A01:2021", 863: "A01:2021",
    295: "A02:2021", 319: "A02:2021", 321: "A02:2021", 327: "A02:2021", 328: "A02:2021", 330: "A02:2021",
    916: "A02:2021",
    20: "A03:2021", 77: "A03:2021", 78: "A03:2021", 79: "A03:2021", 89: "A03:2021", 94: "A03:2021", 117: "A03:2021",
    209: "A04:2021", 400: "A04:2021", 770: "A04:2021", 1088: "A04:2021",
    16: "A05:2021", 611: "A05:2021", 703: "A05:2021", 1051: "A05:2021",
    1104: "A06:2021", 1357: "A06:2021", 1395: "A06:2021",
    259: "A07:2021", 287: "A07:2021", 306: "A07:2021", 798: "A07:2021", 1392: "A07:2021",
    494: "A08:2021", 502: "A08:2021",
    223: "A09:2021", 532: "A09:2021", 778: "A09:2021",
    918: "A10:2021",
}

# Default severity for findings that only the LLM reported (its own rating is kept as a hint).
CWE_SEVERITY: Dict[int, str] = {
    **{c: "CRITICAL" for c in (77, 78, 94, 502)},
    **{c: "HIGH" for c in (22, 79, 89, 120, 121, 259, 287, 295, 306, 319, 327, 416, 434, 611, 787, 798, 862, 863,
                           918, 1392, 1395)},
    **{c: "MEDIUM" for c in (20, 200, 209, 250, 269, 321, 328, 330, 352, 400, 494, 532, 601, 668, 732, 770, 916,
                             1088, 1104)},
    **{c: "LOW" for c in (16, 117, 223, 703, 778, 1051, 1357)},
}

DEFAULT_STRIDE = (_T,)


def _num(cwe: str) -> int:
    try:
        return int(str(cwe).split("-")[-1])
    except ValueError:
        return -1


def stride_for(cwe: str) -> List[str]:
    return list(CWE_STRIDE.get(_num(cwe), DEFAULT_STRIDE))


def owasp_for(cwe: str) -> str:
    return CWE_OWASP.get(_num(cwe), "")


def severity_for(cwe: str) -> str:
    return CWE_SEVERITY.get(_num(cwe), "MEDIUM")
