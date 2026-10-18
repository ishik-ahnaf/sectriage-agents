"""Message protocol: envelope, per-intent content schemas, routing policy, validation.

Every agent-to-agent message is a JSON object with this envelope:

    {
      "message_id": "a1b2c3d4",          # unique id
      "conversation_id": "conv-A-001",   # one conversation per alert
      "step": 3,                         # assigned by the orchestrator
      "timestamp": "2026-10-18T...Z",
      "sender": "classifier",
      "receiver": "validator",
      "intent": "classification_result", # drives which content schema applies
      "content": { ... },                # intent-specific payload
      "constraints": {"format": "json"}, # output constraints for the receiver
      "in_reply_to": "9f8e7d6c"          # id of the message this answers (or null)
    }

Only the standard library is used so the project runs anywhere.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

CATEGORIES = ("brute_force", "phishing", "malware", "port_scan",
              "data_exfiltration", "benign", "unknown")
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
VERDICTS = ("approved", "rejected")


class ProtocolError(ValueError):
    """Raised when a message fails envelope, schema or JSON validation."""

    def __init__(self, issues: list[str] | str):
        self.issues = [issues] if isinstance(issues, str) else list(issues)
        super().__init__("; ".join(self.issues))


# --------------------------------------------------------------------------
# Content schemas: field -> spec. Supported keys: type, required, nonempty,
# enum, min, max, items (element type for lists)
# --------------------------------------------------------------------------
INTENT_SCHEMAS: dict[str, dict[str, dict[str, Any]]] = {
    "classify_alert": {
        "alert_id": {"type": str, "required": True, "nonempty": True},
        "raw": {"type": str, "required": True, "nonempty": True},
        "source": {"type": str, "required": False},
    },
    "classification_result": {
        "alert_id": {"type": str, "required": True, "nonempty": True},
        "category": {"type": str, "required": True, "enum": CATEGORIES},
        "severity": {"type": str, "required": True, "enum": SEVERITIES},
        "confidence": {"type": float, "required": True, "min": 0.0, "max": 1.0},
        "rationale": {"type": str, "required": True, "nonempty": True},
        "evidence": {"type": dict, "required": True},
        "source_text": {"type": str, "required": True, "nonempty": True},
    },
    "revise_classification": {
        "alert_id": {"type": str, "required": True, "nonempty": True},
        "issues": {"type": list, "required": True, "nonempty": True, "items": str},
        "required": {"type": dict, "required": True},
        "attempt": {"type": int, "required": True, "min": 1},
    },
    "validation_result": {
        "alert_id": {"type": str, "required": True, "nonempty": True},
        "verdict": {"type": str, "required": True, "enum": VERDICTS},
        "issues": {"type": list, "required": True, "items": str},
        "classification": {"type": dict, "required": True},
    },
    "route_error": {
        "alert_id": {"type": str, "required": True, "nonempty": True},
        "reason": {"type": str, "required": True, "nonempty": True},
        "bad_receiver": {"type": str, "required": True},
        "original_intent": {"type": str, "required": True},
    },
}

# intent -> (allowed senders, allowed receivers). Enforced by the orchestrator.
ROUTING_POLICY: dict[str, tuple[set[str], set[str]]] = {
    "classify_alert": ({"orchestrator"}, {"classifier"}),
    "classification_result": ({"classifier"}, {"validator"}),
    "revise_classification": ({"validator"}, {"classifier"}),
    "validation_result": ({"validator"}, {"orchestrator"}),
    "route_error": ({"orchestrator"}, {"classifier", "validator"}),
}


def _type_ok(value: Any, expected: type) -> bool:
    if expected is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected is int:
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, expected)


def validate_content(intent: str, content: Any) -> list[str]:
    """Return a list of human-readable problems with `content` for `intent`."""
    schema = INTENT_SCHEMAS.get(intent)
    if schema is None:
        return [f"unknown intent '{intent}'"]
    if not isinstance(content, dict):
        return ["content must be an object"]
    issues: list[str] = []
    for name, spec in schema.items():
        if name not in content:
            if spec.get("required"):
                issues.append(f"content.{name} is required")
            continue
        value = content[name]
        if not _type_ok(value, spec["type"]):
            issues.append(f"content.{name} must be {spec['type'].__name__}")
            continue
        if spec.get("nonempty") and not value:
            issues.append(f"content.{name} must not be empty")
        if "enum" in spec and value not in spec["enum"]:
            issues.append(f"content.{name}='{value}' not in {list(spec['enum'])}")
        if "min" in spec and value < spec["min"]:
            issues.append(f"content.{name} below minimum {spec['min']}")
        if "max" in spec and value > spec["max"]:
            issues.append(f"content.{name} above maximum {spec['max']}")
        if "items" in spec and isinstance(value, list):
            if not all(isinstance(v, spec["items"]) for v in value):
                issues.append(f"content.{name} items must be {spec['items'].__name__}")
    return issues


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Message:
    sender: str
    receiver: str
    intent: str
    content: dict
    conversation_id: str = ""
    constraints: dict = field(default_factory=lambda: {"format": "json"})
    message_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    step: int = 0
    timestamp: str = field(default_factory=_now)
    in_reply_to: str | None = None

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "conversation_id": self.conversation_id,
            "step": self.step,
            "timestamp": self.timestamp,
            "sender": self.sender,
            "receiver": self.receiver,
            "intent": self.intent,
            "content": self.content,
            "constraints": self.constraints,
            "in_reply_to": self.in_reply_to,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @property
    def alert_id(self) -> str:
        if isinstance(self.content, dict):
            return str(self.content.get("alert_id", "-"))
        return "-"

    def summary(self) -> dict:
        return {"msg": self.message_id, "step": self.step, "from": self.sender,
                "to": self.receiver, "intent": self.intent, "alert": self.alert_id}


ENVELOPE_FIELDS = {
    "message_id": str, "conversation_id": str, "step": int, "timestamp": str,
    "sender": str, "receiver": str, "intent": str, "content": dict, "constraints": dict,
}


def validate_message(obj: Any) -> list[str]:
    """Validate the full wire object (envelope + content)."""
    if not isinstance(obj, dict):
        return ["message must be a JSON object"]
    issues: list[str] = []
    for name, expected in ENVELOPE_FIELDS.items():
        if name not in obj:
            issues.append(f"{name} is required")
        elif not _type_ok(obj[name], expected):
            issues.append(f"{name} must be {expected.__name__}")
    if issues:
        return issues
    for name in ("sender", "receiver", "intent", "message_id"):
        if not obj[name].strip():
            issues.append(f"{name} must not be empty")
    if obj["step"] < 0:
        issues.append("step must be >= 0")
    if obj["constraints"].get("format") != "json":
        issues.append("constraints.format must be 'json'")
    if obj.get("in_reply_to") is not None and not isinstance(obj["in_reply_to"], str):
        issues.append("in_reply_to must be string or null")
    if issues:
        return issues
    return validate_content(obj["intent"], obj["content"])


def parse_message(raw: Any) -> Message:
    """Turn whatever an agent returned (JSON text, dict or Message) into a validated
    Message, or raise ProtocolError describing every problem found."""
    if isinstance(raw, Message):
        raw = raw.to_dict()
    if isinstance(raw, (str, bytes)):
        text = raw if isinstance(raw, str) else raw.decode(errors="replace")
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProtocolError(
                f"output is not valid JSON ({exc.msg}): {text[:60]!r}") from exc
    issues = validate_message(raw)
    if issues:
        raise ProtocolError(issues)
    return Message(
        sender=raw["sender"], receiver=raw["receiver"], intent=raw["intent"],
        content=raw["content"], conversation_id=raw["conversation_id"],
        constraints=raw["constraints"], message_id=raw["message_id"],
        step=raw["step"], timestamp=raw["timestamp"], in_reply_to=raw.get("in_reply_to"),
    )


def check_routing_policy(msg: Message) -> list[str]:
    """Is this sender allowed to send this intent to this receiver?"""
    senders, receivers = ROUTING_POLICY[msg.intent]
    issues = []
    if msg.sender not in senders:
        issues.append(f"sender '{msg.sender}' may not send '{msg.intent}'")
    if msg.receiver not in receivers:
        issues.append(f"receiver '{msg.receiver}' may not receive '{msg.intent}'")
    return issues
