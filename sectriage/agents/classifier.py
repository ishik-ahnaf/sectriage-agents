"""Classifier Agent: turns a raw security alert into a structured classification.

Two brains are available:
  * 'rules' (default) - deterministic regex rules, works offline, ideal for testing
  * 'llm'             - calls the Anthropic API (needs `pip install anthropic` and
                        ANTHROPIC_API_KEY). Same protocol, so the orchestrator and
                        validator do not change.
The first pass deliberately ignores traffic volume (a realistic 'quick triage'
weakness); the Validator catches under-triage and the revision loop fixes it.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any

from ..faults import FaultPlan
from ..protocol import SEVERITY_RANK, Message
from ..resilience import AgentCancelled
from .base import BaseAgent

RULES = [  # (category, regex, base severity) - first match wins
    ("phishing", r"phish|verify your|credential harvest|suspicious (link|email)", "high"),
    ("malware", r"-enc\b|encodedcommand|ransom|trojan|mimikatz|malware|macro", "critical"),
    ("brute_force", r"failed password|authentication failure|failed login|invalid user", "medium"),
    ("port_scan", r"probed [\d,]+ ports|port ?scan|nmap", "low"),
    ("data_exfiltration", r"outbound transfer|exfil|large upload", "medium"),
    ("benign", r"logged in successfully|login successful|backup completed", "low"),
]
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
HOST_RE = re.compile(r"\b(?:LAB|FIN|HR|SRV)-[A-Z]+-?\d+\b")
COUNT_RES = [
    ("failed_attempts", re.compile(r"attempts=(\d+)")),
    ("ports_probed", re.compile(r"probed ([\d,]+) ports")),
    ("gb_transferred", re.compile(r"([\d.]+)\s?GB")),
]


class ClassifierAgent(BaseAgent):
    name = "classifier"

    def __init__(self, comm, faults: FaultPlan | None = None, brain: str = "rules",
                 hang_seconds: float = 2.5):
        super().__init__(comm)
        self.faults = faults or FaultPlan()
        self.brain = brain
        self.hang_seconds = hang_seconds
        self._last_output: dict[str, Message] = {}

    # ------------------------------------------------------------------
    def process(self, msg: Message, cancel: threading.Event | None = None) -> Any:
        if msg.intent == "route_error":
            return self._resend_after_route_error(msg)
        if msg.intent == "classify_alert":
            alert_id, raw, required = msg.content["alert_id"], msg.content["raw"], {}
        else:  # revise_classification
            alert_id, required = msg.content["alert_id"], msg.content["required"]
            raw = self._last_output[alert_id].content["source_text"]

        fault = self.faults.next(alert_id)
        if fault:
            self.comm.event(self.name, "FAULT_INJECTED", level="WARNING", alert=alert_id, fault=fault)
        if fault == "timeout":  # simulate a hung model call
            if cancel is not None:
                if cancel.wait(self.hang_seconds):
                    raise AgentCancelled()
            else:
                time.sleep(self.hang_seconds)
        if fault == "malformed_json":
            return "Sure! Here is my analysis: this looks like a port scan, severity low."

        content = self._classify(alert_id, raw, {} if fault == "ignore_feedback" else required)
        if fault in ("bad_category", "stubborn"):
            content["category"] = "recon_activity"
        elif fault == "hallucinated_indicator":
            content["evidence"]["indicators"].append("198.51.100.200")
        elif fault == "wrong_category":
            content["category"] = "phishing" if content["category"] != "phishing" else "malware"

        reply = self.make_reply(msg, "validator", "classification_result", content)
        if fault == "bad_receiver":
            reply.receiver = "validater"  # typo -> unknown receiver
        self._last_output[alert_id] = reply
        return reply.to_dict()

    # ------------------------------------------------------------------
    def _resend_after_route_error(self, msg: Message) -> Any:
        previous = self._last_output[msg.content["alert_id"]]
        fixed = self.make_reply(msg, "validator", "classification_result", previous.content)
        self._last_output[msg.content["alert_id"]] = fixed
        return fixed.to_dict()

    def _classify(self, alert_id: str, raw: str, required: dict) -> dict:
        data = self._classify_llm(raw) if self.brain == "llm" else self._classify_rules(raw)
        floor = required.get("min_severity")
        if floor and SEVERITY_RANK[data["severity"]] < SEVERITY_RANK[floor]:
            data["severity"] = floor
            data["rationale"] += f" Severity raised to {floor} after validator feedback."
        if required.get("suggested_category") and data["category"] != required["suggested_category"]:
            data["category"] = required["suggested_category"]
        if required.get("grounded_only"):
            data["evidence"]["indicators"] = [i for i in data["evidence"]["indicators"] if i in raw]
        return {"alert_id": alert_id, "source_text": raw, **data}

    def _classify_rules(self, raw: str) -> dict:
        category, severity, confidence = "unknown", "low", 0.3
        for cat, pattern, base in RULES:
            if re.search(pattern, raw, re.IGNORECASE):
                category, severity, confidence = cat, base, 0.85
                break
        indicators = IP_RE.findall(raw) + HOST_RE.findall(raw)
        evidence: dict[str, Any] = {"indicators": indicators}
        for metric, regex in COUNT_RES:
            found = regex.search(raw)
            if found and not (metric == "gb_transferred" and category != "data_exfiltration"):
                evidence["metric"] = metric
                evidence["count"] = float(found.group(1).replace(",", ""))
                break
        rationale = (f"Matched '{category}' pattern in alert text; "
                     f"indicators: {', '.join(indicators) or 'none'}.")
        return {"category": category, "severity": severity, "confidence": confidence,
                "rationale": rationale, "evidence": evidence}

    def _classify_llm(self, raw: str) -> dict:  # pragma: no cover - needs network/API key
        import anthropic  # imported lazily so the rules brain needs no dependency
        client = anthropic.Anthropic()
        prompt = (
            "Classify this security alert. Reply with ONLY a JSON object with keys: "
            "category (one of brute_force, phishing, malware, port_scan, data_exfiltration, "
            "benign, unknown), severity (low|medium|high|critical), confidence (0-1), "
            "rationale (string), evidence (object with 'indicators': list of IPs/hosts that "
            "literally appear in the alert, optional 'metric' and numeric 'count').\n\nALERT: " + raw)
        resp = client.messages.create(model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5"),
                                      max_tokens=500, messages=[{"role": "user", "content": prompt}])
        text = resp.content[0].text.strip()
        text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
        return json.loads(text)
