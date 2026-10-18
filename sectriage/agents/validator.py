"""Validator Agent: independently reviews the Classifier's output.

Checks (all deterministic, so results are repeatable):
  1. Grounding   - every indicator must literally appear in the source alert text
  2. Category    - an independent keyword lexicon must not contradict the category
  3. Severity    - policy floors (e.g. >=50 failed logins must be at least 'high')
  4. Quality     - rationale long enough; confidence >= 0.5 unless category is 'unknown'
Approved -> validation_result to orchestrator. Rejected -> revise_classification
back to the classifier with machine-readable `required` hints.
"""
from __future__ import annotations

import threading
from typing import Any

from ..protocol import SEVERITY_RANK, Message
from .base import BaseAgent

LEXICON = [  # independent of the classifier's regexes on purpose
    ("failed password", "brute_force"), ("authentication failure", "brute_force"),
    ("invalid user", "brute_force"), ("failed login", "brute_force"),
    ("phish", "phishing"), ("verify your", "phishing"),
    ("-enc", "malware"), ("encodedcommand", "malware"), ("ransom", "malware"),
    ("mimikatz", "malware"),
    ("probed", "port_scan"), ("port scan", "port_scan"), ("nmap", "port_scan"),
    ("outbound transfer", "data_exfiltration"), ("exfil", "data_exfiltration"),
    ("logged in successfully", "benign"),
]


def severity_floor(category: str, evidence: dict) -> str:
    count = evidence.get("count")
    if category == "brute_force" and isinstance(count, (int, float)) and count >= 50:
        return "high"
    if category == "data_exfiltration" and isinstance(count, (int, float)) and count >= 1:
        return "high"
    if category == "port_scan" and isinstance(count, (int, float)) and count >= 1000:
        return "medium"
    if category in ("malware", "phishing"):
        return "high"
    return "low"


class ValidatorAgent(BaseAgent):
    name = "validator"

    def __init__(self, comm):
        super().__init__(comm)
        self._attempts: dict[str, int] = {}

    def process(self, msg: Message, cancel: threading.Event | None = None) -> Any:
        if msg.intent == "route_error":
            raise RuntimeError("validator has nothing to resend")
        c = msg.content
        alert_id = c["alert_id"]
        self._attempts[alert_id] = self._attempts.get(alert_id, 0) + 1
        issues: list[str] = []
        required: dict[str, Any] = {}

        bad = [i for i in c["evidence"].get("indicators", []) if i not in c["source_text"]]
        if bad:
            issues.append(f"ungrounded indicator(s) not in source: {', '.join(bad)}")
            required["grounded_only"] = True

        text = c["source_text"].lower()
        independent = next((cat for key, cat in LEXICON if key in text), "unknown")
        if independent != "unknown" and independent != c["category"]:
            issues.append(f"category '{c['category']}' contradicts alert text (looks like '{independent}')")
            required["suggested_category"] = independent
        effective_category = required.get("suggested_category", c["category"])

        floor = severity_floor(effective_category, c["evidence"])
        if SEVERITY_RANK[c["severity"]] < SEVERITY_RANK[floor]:
            count = c["evidence"].get("count")
            issues.append(f"severity '{c['severity']}' too low for {effective_category}"
                          f"{f' (count={count:g})' if count is not None else ''}; minimum is '{floor}'")
            required["min_severity"] = floor

        if len(c["rationale"]) < 20:
            issues.append("rationale too short to be useful")
        if c["category"] != "unknown" and c["confidence"] < 0.5:
            issues.append(f"confidence {c['confidence']} below 0.5")

        if issues:
            return self.make_reply(msg, "classifier", "revise_classification", {
                "alert_id": alert_id, "issues": issues, "required": required,
                "attempt": self._attempts[alert_id]}).to_dict()

        notes = ["category 'unknown' - queued for analyst review"] if c["category"] == "unknown" else []
        classification = {k: c[k] for k in ("category", "severity", "confidence", "rationale", "evidence")}
        return self.make_reply(msg, "orchestrator", "validation_result", {
            "alert_id": alert_id, "verdict": "approved", "issues": notes,
            "classification": classification}).to_dict()
