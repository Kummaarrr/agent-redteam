"""Resolve the benign templates into concrete Scenario objects against the seeded world: each
instruction phrasing becomes one scenario, and every SlotRef is checked to point at a real row
so an attack generator can later write a payload into exactly that place.

A slot `ref` is one of: `thread:<id>` (the latest inbound message of the thread), `file:<path>`,
`url:<url>`, `contact:<id>`, `event:<id>`."""

from __future__ import annotations

import json

from redteam.model import Scenario, Slot
from redteam.scenarios.templates import TEMPLATES, Template
from redteam.workspace.world import World


def _resolve_ref(world: World, channel: str, ref: str) -> str:
    """Return a concrete handle the attack generator can target, after checking it exists.
    For a thread slot the handle is the inbound message id (that is where body / subject /
    sender / attachment live)."""
    kind, _, rest = ref.partition(":")
    if kind == "thread":
        m = world.row(
            "SELECT id FROM messages WHERE thread_id = ? AND direction = 'in' ORDER BY sent_at DESC, id DESC LIMIT 1",
            (rest,),
        )
        if not m:
            raise ValueError(f"no inbound message in thread {rest}")
        return f"message:{m['id']}"
    if kind == "file":
        if not world.row("SELECT 1 FROM files WHERE path = ?", (rest,)):
            raise ValueError(f"file not found: {rest}")
        return f"file:{rest}"
    if kind == "url":
        if not world.row("SELECT 1 FROM web_pages WHERE url = ?", (rest,)):
            raise ValueError(f"web page not found: {rest}")
        return f"url:{rest}"
    if kind == "contact":
        if not world.row("SELECT 1 FROM contacts WHERE id = ?", (rest,)):
            raise ValueError(f"contact not found: {rest}")
        return f"contact:{rest}"
    if kind == "event":
        if not world.row("SELECT 1 FROM events WHERE id = ?", (rest,)):
            raise ValueError(f"event not found: {rest}")
        return f"event:{rest}"
    raise ValueError(f"unknown ref kind: {ref}")


def build_scenarios(world: World) -> list[Scenario]:
    scenarios: list[Scenario] = []
    for tpl in TEMPLATES:
        slots = [
            Slot(channel=s.channel, ref=_resolve_ref(world, s.channel, s.ref), label=s.label)
            for s in tpl.slots
        ]
        reads = [_read_ref(s) for s in tpl.reads]
        for i, instruction in enumerate(tpl.instructions):
            scenarios.append(
                Scenario(
                    id=f"{tpl.name}__{i}",
                    template=tpl.name,
                    instruction=instruction,
                    expected=tpl.expected,
                    slots=slots,
                    reads=reads,
                    lookalike=tpl.lookalike,
                    notes=tpl.notes,
                )
            )
    return scenarios


def _read_ref(ref: str) -> str:
    kind, _, rest = ref.partition(":")
    return ref if kind != "thread" else f"thread:{rest}"


def save(world: World, path: str) -> int:
    scenarios = build_scenarios(world)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([s.to_dict() for s in scenarios], f, indent=1, ensure_ascii=False)
    return len(scenarios)


def _template_names() -> list[str]:
    return [t.name for t in TEMPLATES]


__all__ = ["Template", "build_scenarios", "save"]
