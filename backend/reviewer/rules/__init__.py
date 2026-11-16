"""Rule engine: typed rules grouped in packs, matched on Python AST, text or parsed config."""
from typing import List

from .base import FileContext, Match, Rule
from .engine import bandit_findings, run_rules, secret_findings

ALL_RULES: List[Rule] = []


def register(*rules: Rule) -> None:
    known = {r.id for r in ALL_RULES}
    for rule in rules:
        if rule.id in known:
            raise ValueError(f"Duplicate rule id {rule.id}")
        ALL_RULES.append(rule)
        known.add(rule.id)


def rules_by_pack(pack: str) -> List[Rule]:
    return [r for r in ALL_RULES if r.pack == pack]


from . import config, ot_ics  # noqa: E402  (rule packs register themselves below)

register(*ot_ics.RULES)
register(*config.RULES)


__all__ = [
    "ALL_RULES", "FileContext", "Match", "Rule", "bandit_findings", "register", "rules_by_pack",
    "run_rules", "secret_findings",
]
