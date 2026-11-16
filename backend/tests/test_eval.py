import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from eval.harness import (  # noqa: E402
    RecordedAI, Sample, check_thresholds, evaluate, load_dataset, match,
)
from eval.report import render_markdown  # noqa: E402
from reviewer.findings import Finding  # noqa: E402
from reviewer.schemas import AIAnalysisResult  # noqa: E402
from tests.conftest import make_finding  # noqa: E402

DATASET = load_dataset()


def pred(line, rule="R", cwe="CWE-1", file="a.py"):
    return Finding(rule, "t", "c", "text", "LOW", "LOW", file, line, cwe=cwe)


def test_dataset_is_well_formed():
    ids = [s.id for s in DATASET]
    assert 40 <= len(DATASET) <= 60
    assert len(ids) == len(set(ids))
    assert {s.category for s in DATASET} == {"ot", "config", "appsec", "secrets"}
    for s in DATASET:
        lines = s.text.split("\n")
        assert s.language
        for exp in s.expected:
            assert 1 <= exp["line"] <= len(lines), s.id
            assert all(c.startswith("CWE-") for c in exp["cwe"])


def test_dataset_has_vulnerable_and_safe_pairs():
    safe = sum(s.safe for s in DATASET)
    assert safe >= 20 and len(DATASET) - safe >= 20


def test_match_prefers_rule_then_cwe_within_tolerance():
    sample = Sample("x", "ot", "a.py", [{"line": 5, "rule": "OT-1", "cwe": ["CWE-1"]}, {"line": 5, "cwe": ["CWE-2"]}])
    counts = match(sample, [pred(6, "OT-1"), pred(4, "B1", "CWE-2"), pred(5, "B2", "CWE-9"), pred(40, "OT-1")])
    assert counts == {"tp": 2, "fp": 2, "fn": 0}


def test_match_is_one_to_one_and_respects_files():
    sample = Sample("x", "ot", "a.py", [{"line": 5, "cwe": ["CWE-1"]}])
    assert match(sample, [pred(5), pred(5), pred(5, file="b.py")]) == {"tp": 1, "fp": 1, "fn": 0}
    assert match(sample, [pred(8)]) == {"tp": 0, "fp": 1, "fn": 1}


def test_rules_engine_meets_the_ci_thresholds():
    result = evaluate("rules", [s for s in DATASET if s.category == "ot"]).to_dict()
    assert check_thresholds({"rules": result}, 0.9, 0.1) == []


def test_threshold_check_reports_problems():
    bad = {"rules": {"by_category": {"ot": {"recall": 0.5, "fp_rate_safe": 0.5}}}}
    assert len(check_thresholds(bad, 0.9, 0.1)) == 2
    assert check_thresholds({}, 0.9, 0.1) == ["rules engine was not evaluated"]


def test_llm_engines_are_skipped_without_recordings(tmp_path):
    result = evaluate("llm", DATASET[:3], RecordedAI(directory=tmp_path)).to_dict()
    assert result["status"] == "not_run" and result["skipped"] == 3


def test_llm_and_hybrid_with_a_fake_model():
    samples = [s for s in DATASET if s.id in ("py-sqli-vuln", "py-sqli-safe", "js-xss-vuln")]

    def fake_ai(engine, sample_id, context):
        if sample_id == "py-sqli-vuln":
            return AIAnalysisResult(vulnerabilities=[make_finding(file=samples[0].path, line="Line 12", cwe="CWE-89")])
        if sample_id == "py-sqli-safe":
            return AIAnalysisResult(vulnerabilities=[make_finding(file=samples[1].path, line="Line 12", cwe="CWE-89")])
        return None  # no recording for the third sample

    llm = evaluate("llm", samples, fake_ai).to_dict()
    hybrid = evaluate("hybrid", samples, fake_ai).to_dict()

    assert (llm["tp"], llm["fp"], llm["skipped"], llm["status"]) == (1, 1, 1, "partial")
    assert llm["fp_rate_safe"] == 1.0
    assert hybrid["tp"] == 1  # the AI finding merges with Bandit's B608 on the same line


def test_recorded_ai_replays_files(tmp_path):
    path = tmp_path / "llm" / "s1.json"
    path.parent.mkdir()
    path.write_text(AIAnalysisResult(vulnerabilities=[make_finding()]).model_dump_json())

    result = RecordedAI(directory=tmp_path)("llm", "s1", "ctx")
    assert len(result.vulnerabilities) == 1


def test_markdown_is_honest_about_missing_llm_runs():
    results = {e: evaluate(e, DATASET[:2], RecordedAI(directory=Path("does-not-exist"))).to_dict()
               for e in ("rules", "llm")}
    md = render_markdown(results, DATASET[:2], "2026-01-01")

    assert "| LLM only | not run |" in md
    assert "have not been measured yet" in md
    assert "Ground truth lives in `eval/dataset.yaml`" in md


@pytest.mark.parametrize("engine", ["sast", "rules"])
def test_offline_engines_cover_every_sample(engine):
    assert evaluate(engine, DATASET[:4]).to_dict()["samples"] == 4
