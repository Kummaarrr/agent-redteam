"""Build the world and freeze the scenario and attack sets to data/.

uv run python scripts/build_corpus.py
"""

from __future__ import annotations

import sys

from redteam.attacks.generate import build_attacks
from redteam.attacks.generate import save as save_attacks
from redteam.config import DATA_DIR, GENERATED
from redteam.scenarios.build import build_scenarios
from redteam.scenarios.build import save as save_scenarios
from redteam.workspace.world import World


def main() -> int:
    sys.stdout.reconfigure(errors="replace")
    db = GENERATED / "world.db"
    world = World.create(db)
    n_sc = save_scenarios(world, str(DATA_DIR / "scenarios.json"))
    atks = build_attacks(build_scenarios(world))
    n_atk = save_attacks(atks, str(DATA_DIR / "attacks.json"))
    import collections

    by_goal = collections.Counter(a.goal for a in atks)
    by_split = collections.Counter(a.split for a in atks)
    print(f"world: {db}")
    print(f"scenarios: {n_sc} -> {DATA_DIR / 'scenarios.json'}")
    print(f"attacks: {n_atk} -> {DATA_DIR / 'attacks.json'}")
    print(f"  by goal: {dict(by_goal)}")
    print(f"  by split: {dict(by_split)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
