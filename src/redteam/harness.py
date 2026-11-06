"""Run attack cases and benign scenarios against Target A under a defence stack, scoring each.

One case: restore the world to base, plant the payload at its slot, snapshot 'task', run the
agent on the scenario's instruction, score from the resulting state, restore. The world is reused
across cases (cheap) but each case starts clean. Model calls are cached and the ledger caps cost.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from redteam import llm
from redteam.attacks.plant import plant
from redteam.defences.base import Stack
from redteam.defences.layers import set_api_key
from redteam.model import AttackCase, Scenario
from redteam.scoring import AttackScore, benign_done, score_attack
from redteam.target.agent import AgentConfig, run
from redteam.workspace.world import World


@dataclass
class BenignScore:
    scenario_id: str
    template: str
    stack: str
    benign_done: bool
    blocked: bool
    outcome: str

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


def run_attack(
    world: World,
    scenario: Scenario,
    case: AttackCase,
    stack: Stack,
    model: str,
    api_key: str | None = None,
    naive: bool = False,
) -> AttackScore:
    world.restore("base")
    world.set_task(case.id)
    plant(world, case)
    world.snapshot("task")
    set_api_key(stack, api_key)
    trace = run(
        world,
        scenario.instruction,
        AgentConfig(model=model, stack=stack, naive=naive),
        api_key=api_key,
    )
    score = score_attack(world, scenario, case, trace)
    world.restore("base")
    return score


def run_benign(
    world: World,
    scenario: Scenario,
    stack: Stack,
    model: str,
    api_key: str | None = None,
    naive: bool = False,
) -> BenignScore:
    world.restore("base")
    world.set_task(f"benign_{scenario.id}")
    world.snapshot("task")
    set_api_key(stack, api_key)
    trace = run(
        world,
        scenario.instruction,
        AgentConfig(model=model, stack=stack, naive=naive),
        api_key=api_key,
    )
    done = benign_done(world, scenario, trace)
    world.restore("base")
    return BenignScore(
        scenario_id=scenario.id,
        template=scenario.template,
        stack=stack.name,
        benign_done=done,
        blocked=bool(trace.blocked),
        outcome=trace.outcome,
    )


def check_budget() -> None:
    llm.LEDGER.check()
