"""Run the red-team evaluation for one defence stack over a split, against Target A.

    uv run python scripts/run_eval.py --stack D0 --split dev
    uv run python scripts/run_eval.py --stack stack --split test --tag r1 --max-cost 8

Writes evals/results/<stack>_<model>_<split>[_<tag>].json with per-case scores and the aggregate
(attack success rate by goal / channel / technique, detection, and the benign false-block rate on
the benign + look-alike set). A fresh --tag namespaces the cache so a repeat re-runs the model.
"""

from __future__ import annotations

import argparse
import json
import sys

from tqdm import tqdm

from redteam import llm
from redteam.attacks.generate import build_attacks
from redteam.config import GENERATED, RESULTS
from redteam.defences.layers import make_stacks
from redteam.harness import run_attack, run_benign
from redteam.scenarios.build import build_scenarios
from redteam.scoring import aggregate
from redteam.workspace.world import World


def main() -> int:
    sys.stdout.reconfigure(errors="replace")  # Windows consoles: never die on a glyph
    ap = argparse.ArgumentParser()
    ap.add_argument("--stack", default="D0")
    ap.add_argument("--split", default="dev", choices=["dev", "test"])
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--judge-model", default="claude-haiku-5-5")
    ap.add_argument("--tag", default="")
    ap.add_argument(
        "--benign",
        action="store_true",
        help="also score the benign + look-alike set (false blocks)",
    )
    ap.add_argument("--naive", action="store_true", help="use the naive (eager-to-please) target")
    ap.add_argument(
        "--benign-only", action="store_true", help="skip attacks; score only the benign set"
    )
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--goals", default="", help="comma list to restrict goals")
    ap.add_argument("--max-cost", type=float, default=6.0)
    args = ap.parse_args()

    llm.LEDGER.cap_usd = args.max_cost
    if args.tag:
        llm.set_cache_namespace(args.tag)

    world = World(GENERATED / "world.db")
    scenarios = {s.id: s for s in build_scenarios(world)}
    stacks = make_stacks(args.judge_model)
    if args.stack not in stacks:
        raise SystemExit(f"unknown stack {args.stack}; have {sorted(stacks)}")

    cases = [c for c in build_attacks(list(scenarios.values())) if c.split == args.split]
    if args.goals:
        want = set(args.goals.split(","))
        cases = [c for c in cases if c.goal in want]
    if args.limit:
        cases = cases[: args.limit]

    scores = []
    key = args.model.split("-")[1]
    attack_cases = [] if args.benign_only else cases
    for case in tqdm(attack_cases, desc=f"{args.stack}/{args.split}", unit="atk"):
        stack = make_stacks(args.judge_model)[args.stack]  # fresh layer state per case
        try:
            scores.append(
                run_attack(
                    world, scenarios[case.scenario_id], case, stack, args.model, naive=args.naive
                )
            )
        except llm.BudgetExceeded:
            print(f"\nbudget hit after {len(scores)} cases", flush=True)
            break

    agg = aggregate(scores, args.stack)
    out = {
        "stack": args.stack,
        "split": args.split,
        "model": args.model,
        "aggregate": agg,
        "cases": [s.to_dict() for s in scores],
    }

    if args.benign or args.benign_only:
        benign = []
        for sc in tqdm(list(scenarios.values()), desc="benign", unit="task"):
            stack = make_stacks(args.judge_model)[args.stack]
            try:
                benign.append(run_benign(world, sc, stack, args.model, naive=args.naive))
            except llm.BudgetExceeded:
                break
        done = sum(b.benign_done for b in benign)
        blocked = sum(b.blocked for b in benign)
        out["benign"] = {
            "n": len(benign),
            "task_success_pct": round(100 * done / len(benign), 1) if benign else 0.0,
            "false_block_pct": round(100 * blocked / len(benign), 1) if benign else 0.0,
            "scores": [b.to_dict() for b in benign],
        }

    RESULTS.mkdir(parents=True, exist_ok=True)
    suffix = "_benign" if args.benign_only else ""
    name = f"{args.stack}{'-naive' if args.naive else ''}_{key}_{args.split}{suffix}" + (
        f"_{args.tag}" if args.tag else ""
    )
    path = RESULTS / f"{name}.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")

    a = agg
    print(f"\n## {args.stack} / {args.model} / {args.split} ({a['n']} attacks)")
    print(f"| Attack success rate | {a['asr_pct']}% |")
    print(
        f"| Detected | {a['attacks_detected_pct']}% |  silent success | {a['silent_success_pct']}% |"
    )
    print(f"| By goal | {a['by_goal']} |")
    print(f"| Worst technique | {a['worst_technique']} |")
    if args.benign:
        print(
            f"| Benign task success | {out['benign']['task_success_pct']}% | false blocks | {out['benign']['false_block_pct']}% |"
        )
    print(llm.LEDGER.summary(), " -> ", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
