"""Target A: the inbox-and-files assistant as a manual tool-use loop on the Anthropic SDK, with
the defence stack's hooks around tool exposure, every call, every result and the final answer.
Defence-free (D0) it is the agent a careful developer ships; the layers are measured on top."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from redteam import llm
from redteam.defences.base import CallContext, Stack
from redteam.model import ToolCall, Trace
from redteam.target import prompts
from redteam.workspace.tools import TOOLS, Backend, ToolError
from redteam.workspace.world import World


@dataclass
class AgentConfig:
    model: str = "claude-haiku-5-5"
    stack: Stack = field(default_factory=Stack)
    max_turns: int = 14
    max_tool_calls: int = 30
    thinking: bool = False
    naive: bool = False


def run(world: World, instruction: str, cfg: AgentConfig, api_key: str | None = None) -> Trace:
    start = time.perf_counter()
    stack = cfg.stack
    stack.blocked.clear()
    for layer in stack.layers:
        layer.events.clear()
    stack.start(instruction, world)
    backend = Backend(world)
    system = prompts.system_prompt(stack.hardened, stack.system_extra(), naive=cfg.naive)
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": prompts.task_message(instruction)}
    ]
    tool_log: list[ToolCall] = []
    ctx = CallContext(instruction=instruction, tool_log=[], api_key=api_key, model=cfg.model)
    calls = 0
    cost = 0.0
    outcome, answer, error = "failed", "", "no finish call"
    nudged = False

    for _turn in range(cfg.max_turns):
        tools = [t.definition() for t in stack.allowed_tools(TOOLS)] + [prompts.FINISH_TOOL]
        try:
            reply, info = llm.chat(
                cfg.model, system, messages, tools, thinking=cfg.thinking, api_key=api_key
            )
        except llm.BudgetExceeded:
            raise
        except Exception as e:  # model / transport error: the task fails closed
            error = f"model error: {type(e).__name__}: {str(e)[:200]}"
            break
        calls += 1
        cost += info.cost_usd
        messages.append({"role": "assistant", "content": reply["content"]})
        tool_uses = [b for b in reply["content"] if b.get("type") == "tool_use"]
        if not tool_uses:
            if not nudged and _turn + 1 < cfg.max_turns:
                nudged = True
                messages.append(
                    {"role": "user", "content": "Continue: use the tools, then call `finish`."}
                )
                continue
            break
        results: list[dict[str, Any]] = []
        finished = False
        for tu in tool_uses:
            name, args = tu["name"], tu.get("input") or {}
            if name == "finish":
                outcome = str(args.get("outcome", "failed"))
                answer = str(args.get("answer", ""))
                problem = stack.check_answer(answer, ctx)
                if problem:
                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tu["id"],
                            "content": f"ANSWER BLOCKED: {problem}. Rewrite the answer without it and call finish again.",
                            "is_error": True,
                        }
                    )
                    outcome, answer = "failed", ""
                    continue
                error = ""
                finished = True
                results.append({"type": "tool_result", "tool_use_id": tu["id"], "content": "ok"})
                continue
            text, is_error = _call(
                backend, stack, name, args, ctx, len(tool_log) >= cfg.max_tool_calls
            )
            tool_log.append(ToolCall(name, args, is_error, text[:600]))
            ctx.tool_log.append(
                {"tool": name, "args": args, "error": is_error, "result": text[:600]}
            )
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tu["id"],
                    "content": text,
                    "is_error": is_error,
                }
            )
        messages.append({"role": "user", "content": results})
        if finished:
            break

    return Trace(
        outcome=outcome,
        answer=answer,
        tool_log=tool_log,
        blocked=list(stack.blocked),
        security_events=list(stack.events),
        model_calls=calls + stack.model_calls,
        cost_usd=cost + stack.cost_usd,
        seconds=time.perf_counter() - start,
        stack=stack.name,
        error=error,
    )


def _call(
    backend: Backend,
    stack: Stack,
    name: str,
    args: dict[str, Any],
    ctx: CallContext,
    over_cap: bool,
) -> tuple[str, bool]:
    from redteam.workspace.tools import BY_NAME

    spec = BY_NAME.get(name)
    if spec is None or spec not in stack.allowed_tools(TOOLS):
        return f"ERROR: unknown tool {name}", True
    if over_cap:
        return "ERROR: tool call limit reached for this task; call finish.", True
    reason = stack.check_call(spec, args, ctx)
    if reason:
        backend.world.audit(name, "security", args, f"blocked: {reason}")
        return f"NOT EXECUTED: {reason}", True
    try:
        result = backend.call(name, args)
    except ToolError as e:
        return f"ERROR: {e}", True
    text = json.dumps(result, ensure_ascii=False, default=str)
    return stack.present(spec, args, result, text), False
