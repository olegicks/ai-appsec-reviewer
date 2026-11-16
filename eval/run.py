"""CLI: python -m eval.run --engine sast|rules|llm|hybrid|all [--live] [--record] [--write] [--check]"""
import argparse
import sys
from datetime import datetime, timezone

from .harness import ENGINES, ROOT, RecordedAI, check_thresholds, evaluate, load_dataset, to_json
from .report import render_markdown

MIN_OT_RECALL = 0.90
MAX_OT_FP_RATE = 0.10


def _fmt(value) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate SAST, rules, LLM and hybrid engines on the labelled dataset.")
    parser.add_argument("--engine", choices=ENGINES + ("all",), default="all")
    parser.add_argument("--live", action="store_true", help="call the real OpenAI API for llm/hybrid (costs money)")
    parser.add_argument("--record", action="store_true", help="with --live: save responses to eval/recordings/")
    parser.add_argument("--write", action="store_true", help="write docs/EVALUATION.md and the UI's evaluation.json")
    parser.add_argument("--check", action="store_true", help="fail if the OT rule pack drops below the CI thresholds")
    parser.add_argument("--only", nargs="*", help="evaluate only these sample ids (useful with --live)")
    args = parser.parse_args(argv)

    samples = load_dataset()
    if args.only:
        samples = [s for s in samples if s.id in set(args.only)]
    engines = ENGINES if args.engine == "all" else (args.engine,)
    if args.live:
        print(f"LIVE mode: {len(samples)} sample(s) x {len([e for e in engines if e in ('llm', 'hybrid')])} "
              "AI engine(s) will call the OpenAI API.")
    ai = RecordedAI(live=args.live, record=args.record)

    results = {}
    print(f"{'engine':8} {'samples':>7} {'TP':>4} {'FP':>4} {'FN':>4} {'prec':>6} {'recall':>6} {'F1':>6} {'FP/safe':>8}")
    for engine in engines:
        r = evaluate(engine, samples, ai).to_dict()
        results[engine] = r
        if r["status"] == "not_run":
            print(f"{engine:8} {'-':>7}  no recorded responses (run with --live --record)")
            continue
        print(f"{engine:8} {r['samples']:>7} {r['tp']:>4} {r['fp']:>4} {r['fn']:>4} {_fmt(r['precision']):>6} "
              f"{_fmt(r['recall']):>6} {_fmt(r['f1']):>6} {_fmt(r['fp_rate_safe']):>8}")

    if args.write:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        (ROOT / "docs").mkdir(exist_ok=True)
        (ROOT / "docs" / "EVALUATION.md").write_text(render_markdown(results, samples, stamp), encoding="utf-8")
        (ROOT / "frontend" / "src" / "data" / "evaluation.json").write_text(to_json(results, stamp) + "\n",
                                                                           encoding="utf-8")
        print("Wrote docs/EVALUATION.md and frontend/src/data/evaluation.json")

    if args.check:
        problems = check_thresholds(results, MIN_OT_RECALL, MAX_OT_FP_RATE)
        if problems:
            print("THRESHOLD CHECK FAILED: " + "; ".join(problems))
            return 1
        print(f"Threshold check passed (OT recall >= {MIN_OT_RECALL}, OT FP rate <= {MAX_OT_FP_RATE}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
