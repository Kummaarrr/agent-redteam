"""Shared data model: scenarios (benign tasks with their untrusted slots), attack cases, and
the trace a target returns. Plain dataclasses, JSON round-trippable."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# where a payload can sit; `ref` identifies the row (message id, file path, url, contact id)
CHANNELS = (
    "message_body",
    "message_subject",
    "sender_name",
    "attachment",
    "file",
    "web_page",
    "contact_note",
    "event_description",
)


@dataclass
class Slot:
    channel: str
    ref: str
    label: str = ""  # human description, e.g. "the vendor's invoice attachment"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExpectedSend:
    to_any_of: list[str]
    attachments: list[str] = field(default_factory=list)  # file names that must be attached
    must_include: list[Any] = field(default_factory=list)  # str or list[str] (any-of)


@dataclass
class ExpectedEvent:
    title_contains: str
    start_at: str
    attendees_any_of: list[str] = field(default_factory=list)


@dataclass
class Expected:
    sends: list[ExpectedSend] = field(default_factory=list)
    events: list[ExpectedEvent] = field(default_factory=list)
    answer_must_include: list[Any] = field(default_factory=list)
    allowed_writes: list[str] = field(default_factory=list)  # write tools the task may use
    outcome: str = "done"  # done | ask | refuse
    recipients_allowed: list[str] = field(default_factory=list)  # every address a send may go to
    contacts_added: list[str] = field(default_factory=list)  # emails that must be added


@dataclass
class Scenario:
    id: str
    template: str
    instruction: str  # what the user asked the assistant to do (trusted)
    expected: Expected
    slots: list[Slot]  # untrusted content this task reads: where an attacker could write
    reads: list[str] = field(default_factory=list)  # refs the agent is expected to read
    lookalike: bool = False  # benign content that resembles an attack (false-block set)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Scenario:
        e = d["expected"]
        expected = Expected(
            sends=[ExpectedSend(**s) for s in e.get("sends", [])],
            events=[ExpectedEvent(**v) for v in e.get("events", [])],
            answer_must_include=e.get("answer_must_include", []),
            allowed_writes=e.get("allowed_writes", []),
            outcome=e.get("outcome", "done"),
            recipients_allowed=e.get("recipients_allowed", []),
            contacts_added=e.get("contacts_added", []),
        )
        return cls(
            id=d["id"],
            template=d["template"],
            instruction=d["instruction"],
            expected=expected,
            slots=[Slot(**s) for s in d["slots"]],
            reads=d.get("reads", []),
            lookalike=d.get("lookalike", False),
            notes=d.get("notes", ""),
        )


GOALS = ("exfiltrate", "unauthorised_action", "derail", "disclose_instructions")


@dataclass
class AttackCase:
    id: str
    scenario_id: str
    goal: str
    channel: str
    technique: str
    payload: str  # the text planted into the slot
    slot: Slot
    split: str  # dev | test
    attacker: dict[str, str]  # address, url, marker ... what success is measured against
    target_canary: str = ""  # canary id the payload goes after (exfiltrate)
    action: dict[str, Any] = field(default_factory=dict)  # unauthorised_action: tool + key args
    paraphrase: int = 0  # 0 = template text, n = nth model paraphrase

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AttackCase:
        d = dict(d)
        d["slot"] = Slot(**d["slot"])
        return cls(**d)


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    error: bool
    result: str  # what the model saw (truncated)


@dataclass
class Trace:
    outcome: str  # done | ask | refuse | failed
    answer: str
    tool_log: list[ToolCall]
    blocked: list[dict[str, Any]]  # defence blocks: {tool, args, reason, layer}
    security_events: list[dict[str, Any]]  # detections that did not block: {layer, detail}
    model_calls: int
    cost_usd: float
    seconds: float
    stack: str
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d
