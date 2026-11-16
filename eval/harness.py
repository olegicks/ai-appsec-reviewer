"""Evaluation harness: runs each engine over the labelled dataset and computes precision / recall / F1.

Engines
  sast   - Bandit only (Python), standard-mode noise filter
  rules  - deterministic rule packs (OT/ICS, config) + secret scanner
  llm    - the LLM alone, given the redacted code without any deterministic findings
  hybrid - the full pipeline: deterministic engines + LLM review, merged by the production triage logic

The llm and hybrid engines use recorded responses from eval/recordings/ unless --live is passed.
"""
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ["OSV_ENABLED"] = "false"  # the dataset has no manifests; never touch the network from the eval

import yaml  # noqa: E402

from reviewer.analysis import build_findings  # noqa: E402
from reviewer.findings import Finding  # noqa: E402
from reviewer.pipeline import LANGUAGE_BY_EXT, PipelineContext, scan_file  # noqa: E402
from reviewer.rules.config import detect_kind  # noqa: E402
from reviewer.schemas import AIAnalysisResult  # noqa: E402
from reviewer.triage import apply_ai, filter_noise  # noqa: E402

DATASET = ROOT / "eval" / "dataset.yaml"
RECORDINGS = ROOT / "eval" / "recordings"
LINE_TOLERANCE = 2
ENGINES = ("sast", "rules", "llm", "hybrid")
RULE_ENGINES = {"python_ast", "text", "config", "secrets"}
PARANOIA = "standard"


@dataclass
class Sample:
    id: str
    category: str
    path: str
    expected: List[dict]

    @property
    def safe(self) -> bool:
        return not self.expected

    @property
    def language(self) -> str:
        ext = os.path.splitext(self.path)[1].lower()
        if ext in LANGUAGE_BY_EXT:
            return LANGUAGE_BY_EXT[ext]
        kind = detect_kind(os.path.basename(self.path), self.text)
        if kind is None:
            raise ValueError(f"Cannot determine the language of {self.path}")
        return kind

    @property
    def text(self) -> str:
        return (ROOT / self.path).read_text(encoding="utf-8")


def load_dataset(path: Path = DATASET) -> List[Sample]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [Sample(s["id"], s["category"], s["path"], s.get("expected") or []) for s in data["samples"]]


# --- AI providers -----------------------------------------------------------------------------

AIProvider = Callable[[str, str, str], Optional[AIAnalysisResult]]  # (engine, sample_id, context) -> result


class RecordedAI:
    """Replays eval/recordings/<engine>/<sample>.json; with live=True calls the real API (and can record)."""

    def __init__(self, live: bool = False, record: bool = False, directory: Path = RECORDINGS):
        self.live, self.record, self.directory = live, record, directory

    def __call__(self, engine: str, sample_id: str, context: str) -> Optional[AIAnalysisResult]:
        path = self.directory / engine / f"{sample_id}.json"
        if not self.live:
            if not path.exists():
                return None
            return AIAnalysisResult.model_validate_json(path.read_text(encoding="utf-8"))

        from reviewer.llm import run_ai_analysis

        result = run_ai_analysis(context, PARANOIA)
        if self.record:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        return result


# --- prediction -----------------------------------------------------------------------------

def _scan(sample: Sample):
    workdir = tempfile.mkdtemp(prefix="appsec-eval-")
    try:
        return scan_file(sample.path, sample.language, sample.text, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def llm_only_context(scan) -> str:
    return (
        f"\n--- FILE: {scan.ctx.path} ---\nLANGUAGE: {scan.ctx.language}\n"
        f"DETERMINISTIC FINDINGS (review each id):\nnone\nCODE:\n{scan.ctx.text}\n"
    )


def predict(sample: Sample, engine: str, ai: Optional[AIProvider] = None) -> Optional[List[Finding]]:
    """Findings of one engine for one sample, or None when the engine could not run (no recording)."""
    scan = _scan(sample)
    # Findings of different engines on the same line/CWE are merged, so look at every reporting engine.
    if engine == "sast":
        return [f for f in filter_noise(scan.findings, PARANOIA) if "bandit" in f.engines]
    if engine == "rules":
        return [f for f in scan.findings if set(f.engines) & RULE_ENGINES]

    ai = ai or RecordedAI()
    if engine == "llm":
        result = ai("llm", sample.id, llm_only_context(scan))
        return None if result is None else apply_ai([], result, PARANOIA, {scan.ctx.path: scan.ctx})
    if engine == "hybrid":
        ctx = PipelineContext()
        ctx.add(scan)
        result = ai("hybrid", sample.id, ctx.text)
        return None if result is None else build_findings(ctx, result, PARANOIA)
    raise ValueError(f"Unknown engine {engine}")


# --- matching and metrics -------------------------------------------------------------------

def match(sample: Sample, predicted: List[Finding]) -> Dict[str, int]:
    """Greedy one-to-one matching: rule id first, then CWE, within LINE_TOLERANCE lines."""
    remaining = [f for f in predicted if f.file == sample.path]
    unmatched_expected = list(sample.expected)
    tp = 0
    for by_rule in (True, False):
        for exp in list(unmatched_expected):
            for f in remaining:
                if abs(f.line - exp["line"]) > LINE_TOLERANCE:
                    continue
                ok = f.rule_id == exp.get("rule") if by_rule else f.cwe in exp.get("cwe", [])
                if ok:
                    tp += 1
                    remaining.remove(f)
                    unmatched_expected.remove(exp)
                    break
    return {"tp": tp, "fp": len(remaining), "fn": len(unmatched_expected)}


def _ratio(num: int, den: int) -> Optional[float]:
    return round(num / den, 3) if den else None


@dataclass
class Score:
    samples: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    safe_samples: int = 0
    safe_with_findings: int = 0

    def add(self, sample: Sample, counts: Dict[str, int]) -> None:
        self.samples += 1
        self.tp += counts["tp"]
        self.fp += counts["fp"]
        self.fn += counts["fn"]
        if sample.safe:
            self.safe_samples += 1
            self.safe_with_findings += int(counts["fp"] > 0)

    def metrics(self) -> Dict:
        precision = _ratio(self.tp, self.tp + self.fp)
        recall = _ratio(self.tp, self.tp + self.fn)
        f1 = round(2 * precision * recall / (precision + recall), 3) if precision and recall else (
            0.0 if precision is not None and recall is not None else None)
        return {
            "samples": self.samples, "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "precision": precision, "recall": recall, "f1": f1,
            "safe_samples": self.safe_samples,
            "fp_rate_safe": _ratio(self.safe_with_findings, self.safe_samples),
        }


@dataclass
class EngineResult:
    engine: str
    total: Score = field(default_factory=Score)
    by_category: Dict[str, Score] = field(default_factory=dict)
    skipped: int = 0

    def to_dict(self) -> Dict:
        return {
            "engine": self.engine,
            "status": "not_run" if self.total.samples == 0 else ("partial" if self.skipped else "ok"),
            "skipped": self.skipped,
            **self.total.metrics(),
            "by_category": {k: v.metrics() for k, v in sorted(self.by_category.items())},
        }


def evaluate(engine: str, samples: List[Sample], ai: Optional[AIProvider] = None) -> EngineResult:
    result = EngineResult(engine)
    for sample in samples:
        predicted = predict(sample, engine, ai)
        if predicted is None:
            result.skipped += 1
            continue
        counts = match(sample, predicted)
        result.total.add(sample, counts)
        result.by_category.setdefault(sample.category, Score()).add(sample, counts)
    return result


def check_thresholds(results: Dict[str, Dict], min_recall: float, max_fp_rate: float) -> List[str]:
    """CI gate on the deterministic OT rule pack."""
    rules = results.get("rules")
    if not rules:
        return ["rules engine was not evaluated"]
    ot = rules["by_category"].get("ot", {})
    problems = []
    if (ot.get("recall") or 0) < min_recall:
        problems.append(f"OT rule recall {ot.get('recall')} < {min_recall}")
    if (ot.get("fp_rate_safe") or 0) > max_fp_rate:
        problems.append(f"OT false-positive rate on safe samples {ot.get('fp_rate_safe')} > {max_fp_rate}")
    return problems


def to_json(results: Dict[str, Dict], generated_at: str) -> str:
    return json.dumps({"generated_at": generated_at, "line_tolerance": LINE_TOLERANCE, "engines": results}, indent=2)
