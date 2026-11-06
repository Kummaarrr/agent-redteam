"""Run the adaptive attacker over a slice of the test attacks and record every round.

    uv run python scripts/run_adaptive.py --engine ladder --limit 40 --rounds 5
    uv run python scripts/run_adaptive.py --engine model --attacker-model claude-sonnet-5-5 --limit 20

Writes evals/results/adaptive_<engine>_<stack>.json with per-case rounds and the summary (how
many cases ever succeeded, at which round, and - for the model engine - how often the attacker
model declined to author the payload)."""

from __future__ import annotations

import argparse
import json
import sys

from tqdm import tqdm

from redteam import llm
from redteam.attacks.adaptive import run_adaptive
from redteam.attacks.generate import build_attacks
from redteam.config import GENERATED, RESULTS
from redteam.defences.layers import make_stacks
from redteam.scenarios.build import build_scenarios
from redteam.workspace.world import World


def main() -> int:
    sys.stdout.reconfigure(errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="ladder", choices=["ladder", "model"])
    ap.add_argument("--stack", default="D0")
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--attacker-model", default="claude-sonnet-5-5")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--naive", action="store_true")
    ap.add_argument("--max-cost", type=float, default=10.0)
    args = ap.parse_args()

    llm.LEDGER.cap_usd = args.max_cost
    world = World(GENERATED / "world.db")
    scenarios = {s.id: s for s in build_scenarios(world)}
    cases = [c for c in build_attacks(list(scenarios.values())) if c.split == "test"]

    # a spread across goals and channels, strongest vectors first
    cases.sort(key=lambda c: (c.goal, c.channel, c.technique))
    seen: dict[tuple[str, str], int] = {}
    pick = []
    for c in cases:
        k = (c.goal, c.channel)
        if seen.get(k, 0) < max(1, args.limit // 12):
            seen[k] = seen.get(k, 0) + 1
            pick.append(c)
        if len(pick) >= args.limit:
            break

    results = []
    for case in tqdm(pick, desc=f"adaptive/{args.engine}", unit="case"):
        stack = make_stacks(args.model)[args.stack]
        try:
            r = run_adaptive(
                world,
                scenarios[case.scenario_id],
                case,
                stack,
                args.model,
                engine=args.engine,
                attacker_model=args.attacker_model,
                rounds=args.rounds,
            )
        except llm.BudgetExceeded:
            print(f"\nbudget hit after {len(results)} cases", flush=True)
            break
        results.append(r)

    n = len(results)
    succ = sum(r.succeeded for r in results)
    declined = sum(r.attacker_declined for r in results)
    out = {
        "engine": args.engine,
        "stack": args.stack,
        "model": args.model,
        "attacker_model": args.attacker_model if args.engine == "model" else None,
        "rounds": args.rounds,
        "n": n,
        "ever_succeeded": succ,
        "asr_pct": round(100 * succ / n, 1) if n else 0.0,
        "attacker_declined": declined,
        "results": [r.to_dict() for r in results],
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"adaptive_{args.engine}_{args.stack}{'-naive' if args.naive else ''}.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n## adaptive {args.engine} / {args.stack} ({n} cases, up to {args.rounds} rounds)")
    print(f"| Ever succeeded | {succ}/{n} ({out['asr_pct']}%) |")
    if args.engine == "model":
        print(f"| Attacker model declined | {declined}/{n} |")
    print(llm.LEDGER.summary(), " -> ", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
