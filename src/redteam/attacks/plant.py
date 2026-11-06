"""Plant an attack payload into the workspace at the slot it targets, inside a snapshot that is
restored after the case runs. The payload is written into exactly the field the scenario's agent
is expected to read, so a success means the agent acted on content it was always going to see -
not on anything injected into its own instructions."""

from __future__ import annotations

import json

from redteam.model import AttackCase, Slot
from redteam.workspace.world import World


def plant(world: World, case: AttackCase) -> None:
    """Write `case.payload` into the slot. Assumes the world is at a clean snapshot; the caller
    restores afterwards."""
    slot = case.slot
    kind, _, ref = slot.ref.partition(":")
    with world.transaction():
        if kind == "message":
            _plant_message(world, slot, ref, case.payload)
        elif kind == "file":
            _append_text(world, "files", "path", ref, "text", case.payload)
        elif kind == "url":
            _append_text(world, "web_pages", "url", ref, "text", case.payload)
        elif kind == "contact":
            _append_text(world, "contacts", "id", ref, "note", case.payload)
        elif kind == "event":
            _append_text(world, "events", "id", ref, "description", case.payload)
        else:
            raise ValueError(f"cannot plant into {slot.ref}")


def _plant_message(world: World, slot: Slot, mid: str, payload: str) -> None:
    row = world.row("SELECT * FROM messages WHERE id = ?", (mid,))
    if not row:
        raise ValueError(f"message {mid} not found")
    if slot.channel == "message_body":
        world.execute("UPDATE messages SET body = body || ? WHERE id = ?", ("\n\n" + payload, mid))
    elif slot.channel == "message_subject":
        world.execute(
            "UPDATE messages SET subject = subject || ? WHERE id = ?", (" " + payload, mid)
        )
    elif slot.channel == "sender_name":
        world.execute(
            "UPDATE messages SET from_name = from_name || ? WHERE id = ?", (" " + payload, mid)
        )
    elif slot.channel == "attachment":
        atts = json.loads(row["attachments"] or "[]")
        if atts:
            atts[0]["text"] = atts[0].get("text", "") + "\n\n" + payload
        else:
            atts = [{"name": "note.txt", "mime": "text/plain", "text": payload}]
        world.execute("UPDATE messages SET attachments = ? WHERE id = ?", (json.dumps(atts), mid))
    else:
        raise ValueError(f"message slot cannot carry channel {slot.channel}")


def _append_text(
    world: World, table: str, key_col: str, key: str, text_col: str, payload: str
) -> None:
    row = world.row(f"SELECT {text_col} FROM {table} WHERE {key_col} = ?", (key,))
    if row is None:
        raise ValueError(f"{table} row {key} not found")
    world.execute(
        f"UPDATE {table} SET {text_col} = {text_col} || ? WHERE {key_col} = ?",
        ("\n\n" + payload, key),
    )
