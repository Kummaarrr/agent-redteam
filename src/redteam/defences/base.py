"""Defence layers as hooks around the agent loop. A `Stack` composes layers in order; the agent
calls the stack, never a layer directly, so any target with the same hook points can use them.

Hook points (all synchronous):
- `start(instruction, world)`: the trusted request is known; derive scope here (D4, D7).
- `system_extra()`: text appended to the system prompt (D1, D2 nonce).
- `allowed_tools(tools)`: hide tools the task cannot need (D4).
- `check_call(tool, args, context)`: block a call before it runs; return a reason or None.
- `present(tool, args, result, text)`: transform what the model sees of a result (D2, D3).
- `check_answer(answer)`: block or rewrite the final answer (D5).

A layer records `events` (detections that did not block) and the stack records `blocked`."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from redteam.workspace.tools import ToolSpec
from redteam.workspace.world import World


@dataclass
class CallContext:
    """What a layer may look at when judging a call."""

    instruction: str
    tool_log: list[dict[str, Any]]
    api_key: str | None = None
    model: str = "claude-haiku-5-5"


class Defence:
    name = "base"

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.cost_usd = 0.0
        self.model_calls = 0

    def event(self, detail: str, **extra: Any) -> None:
        self.events.append({"layer": self.name, "detail": detail[:300], **extra})

    # hooks ------------------------------------------------------------
    def start(self, instruction: str, world: World) -> None:
        return None

    def system_extra(self) -> str:
        return ""

    def allowed_tools(self, tools: list[ToolSpec]) -> list[ToolSpec]:
        return tools

    def check_call(self, tool: ToolSpec, args: dict[str, Any], ctx: CallContext) -> str | None:
        return None

    def present(
        self, tool: ToolSpec, args: dict[str, Any], result: dict[str, Any], text: str
    ) -> str:
        return text

    def check_answer(self, answer: str, ctx: CallContext) -> str | None:
        return None


@dataclass
class Stack:
    layers: list[Defence] = field(default_factory=list)
    name: str = "D0"
    blocked: list[dict[str, Any]] = field(default_factory=list)

    def start(self, instruction: str, world: World) -> None:
        for layer in self.layers:
            layer.start(instruction, world)

    def system_extra(self) -> str:
        return "\n\n".join(x for x in (layer.system_extra() for layer in self.layers) if x)

    def allowed_tools(self, tools: list[ToolSpec]) -> list[ToolSpec]:
        for layer in self.layers:
            tools = layer.allowed_tools(tools)
        return tools

    def check_call(self, tool: ToolSpec, args: dict[str, Any], ctx: CallContext) -> str | None:
        for layer in self.layers:
            reason = layer.check_call(tool, args, ctx)
            if reason:
                self.blocked.append(
                    {"tool": tool.name, "args": args, "reason": reason, "layer": layer.name}
                )
                return f"{reason} [{layer.name}]"
        return None

    def present(
        self, tool: ToolSpec, args: dict[str, Any], result: dict[str, Any], text: str
    ) -> str:
        for layer in self.layers:
            text = layer.present(tool, args, result, text)
        return text

    def check_answer(self, answer: str, ctx: CallContext) -> str | None:
        for layer in self.layers:
            reason = layer.check_answer(answer, ctx)
            if reason:
                self.blocked.append(
                    {
                        "tool": "finish",
                        "args": {"answer": answer[:200]},
                        "reason": reason,
                        "layer": layer.name,
                    }
                )
                return f"{reason} [{layer.name}]"
        return None

    @property
    def events(self) -> list[dict[str, Any]]:
        return [e for layer in self.layers for e in layer.events]

    @property
    def cost_usd(self) -> float:
        return sum(layer.cost_usd for layer in self.layers)

    @property
    def model_calls(self) -> int:
        return sum(layer.model_calls for layer in self.layers)

    @property
    def hardened(self) -> bool:
        return any(layer.name == "D1" for layer in self.layers)
