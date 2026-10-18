"""Orchestrator: routes messages between agents and enforces every guardrail.

Coordination pattern: supervisor-managed review loop (worker = Classifier,
reviewer = Validator). One conversation per alert.

Guardrails enforced here
  * every message is parsed + schema-validated before it is routed
  * receiver must be registered; sender/intent/receiver must satisfy ROUTING_POLICY
  * each agent call has a timeout and a bounded number of retries
  * max revision rounds per alert (max_revisions) and max routed steps (max_steps)
  * any unrecoverable problem ends in a safe fallback ("needs_human_review")
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from .logger import CommLog
from .protocol import Message, ProtocolError, check_routing_policy, parse_message
from .resilience import AgentTimeout, run_with_timeout


@dataclass
class ConversationState:
    conversation_id: str
    alert_id: str
    step: int = 0
    revisions: int = 0
    retries: int = 0
    route_errors: int = 0
    trace: list[str] = field(default_factory=list)


class Orchestrator:
    name = "orchestrator"

    def __init__(self, agents: dict, comm: CommLog, max_steps: int = 20, max_revisions: int = 3,
                 max_retries: int = 2, agent_timeout_s: float = 1.0):
        self.agents = agents
        self.comm = comm
        self.max_steps = max_steps
        self.max_revisions = max_revisions
        self.max_retries = max_retries
        self.agent_timeout_s = agent_timeout_s

    # ------------------------------------------------------------------
    def process_alert(self, alert: dict) -> dict:
        started = time.perf_counter()
        st = ConversationState(f"conv-{alert['alert_id']}", alert["alert_id"])
        self.comm.event(self.name, "CONVERSATION_START", conv=st.conversation_id,
                        max_steps=self.max_steps, max_revisions=self.max_revisions,
                        timeout_s=self.agent_timeout_s)
        first = Message("orchestrator", "classifier", "classify_alert",
                        {"alert_id": alert["alert_id"], "raw": alert["raw"],
                         "source": alert.get("source", "unknown")},
                        conversation_id=st.conversation_id)
        pending: deque[Message] = deque([first])
        result = None

        while pending and result is None:
            msg = pending.popleft()
            if st.step >= self.max_steps:
                result = self._fallback(st, "max_steps_exceeded")
                break
            st.step += 1
            msg.step = st.step
            st.trace.append(f"{msg.sender}->{msg.receiver}:{msg.intent}")

            policy = check_routing_policy(msg)
            if msg.receiver not in self.agents and msg.receiver != self.name:
                result = self._route_error(st, msg, f"unknown receiver '{msg.receiver}'", pending)
                continue
            if policy:
                result = self._route_error(st, msg, "; ".join(policy), pending)
                continue

            self.comm.event(self.name, "ROUTED", **msg.summary())

            if msg.receiver == self.name:  # terminal message
                result = self._finalize(st, msg)
                continue
            if msg.intent == "revise_classification":
                if st.revisions >= self.max_revisions:
                    self.comm.event(self.name, "MAX_ITERATIONS", level="WARNING",
                                    alert=st.alert_id, revisions=st.revisions)
                    result = self._fallback(st, "max_iterations_exceeded")
                    continue
                st.revisions += 1
                self.comm.event(self.name, "REVISION_ROUND", alert=st.alert_id,
                                round=st.revisions, issues=" | ".join(msg.content["issues"]))

            reply, failure = self._call_agent(msg, st)
            if reply is None:
                result = self._fallback(st, failure)
                continue
            pending.append(reply)

        if result is None:
            result = self._fallback(st, "no_result")
        result.update(steps=st.step, revisions=st.revisions, retries=st.retries,
                      elapsed_s=round(time.perf_counter() - started, 2), trace=st.trace)
        self.comm.event(self.name, "CONVERSATION_END", alert=st.alert_id, status=result["status"],
                        steps=st.step, revisions=st.revisions, retries=st.retries,
                        elapsed_s=result["elapsed_s"])
        return result

    # ------------------------------------------------------------------
    def _call_agent(self, msg: Message, st: ConversationState):
        """Deliver msg to its receiver; retry on timeout/crash/invalid output.

        Returns (reply, None) on success or (None, fallback_reason) when retries run out."""
        agent = self.agents[msg.receiver]
        for attempt in range(1, self.max_retries + 2):
            try:
                raw = run_with_timeout(agent.handle, (msg,), self.agent_timeout_s)
                reply = parse_message(raw)
                if reply.sender != msg.receiver:
                    raise ProtocolError(f"sender spoofing: expected '{msg.receiver}', got '{reply.sender}'")
                return reply, None
            except AgentTimeout as exc:
                kind, detail = "TIMEOUT", str(exc)
            except ProtocolError as exc:
                kind, detail = "INVALID_OUTPUT", str(exc)
            except Exception as exc:  # noqa: BLE001 - agent crash must not kill the run
                kind, detail = "AGENT_ERROR", f"{type(exc).__name__}: {exc}"
            self.comm.event(self.name, kind, level="ERROR", agent=msg.receiver, alert=st.alert_id,
                            attempt=f"{attempt}/{self.max_retries + 1}", detail=detail)
            if attempt <= self.max_retries:
                st.retries += 1
                self.comm.event(self.name, "RETRY", level="WARNING", agent=msg.receiver,
                                alert=st.alert_id, msg=msg.message_id)
        return None, f"{kind.lower()}_retries_exhausted"

    def _route_error(self, st, bad: Message, reason: str, pending: deque):
        st.route_errors += 1
        self.comm.event(self.name, "ROUTE_ERROR", level="ERROR", **bad.summary(), reason=reason)
        if st.route_errors > self.max_retries or bad.sender not in self.agents:
            return self._fallback(st, "unroutable_message")
        pending.append(Message("orchestrator", bad.sender, "route_error",
                               {"alert_id": st.alert_id, "reason": reason,
                                "bad_receiver": bad.receiver, "original_intent": bad.intent},
                               conversation_id=st.conversation_id, in_reply_to=bad.message_id))
        return None

    def _finalize(self, st, msg: Message) -> dict:
        c = msg.content
        self.comm.event(self.name, "FINAL", alert=st.alert_id, verdict=c["verdict"],
                        category=c["classification"].get("category"),
                        severity=c["classification"].get("severity"))
        return {"alert_id": st.alert_id, "status": "approved",
                "classification": c["classification"], "notes": c["issues"]}

    def _fallback(self, st, reason: str) -> dict:
        self.comm.event(self.name, "FALLBACK", level="WARNING", alert=st.alert_id, reason=reason,
                        action="needs_human_review")
        return {"alert_id": st.alert_id, "status": "fallback", "fallback_reason": reason,
                "classification": {"category": "unknown", "severity": "medium", "confidence": 0.0,
                                   "rationale": f"Automatic triage failed ({reason}); human review required.",
                                   "evidence": {}}, "notes": ["needs_human_review"]}
