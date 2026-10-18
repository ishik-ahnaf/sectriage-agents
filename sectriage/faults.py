"""Fault injection so failure handling can be demonstrated and tested repeatably.

A FaultPlan maps alert_id -> list of fault names. Each time the classifier handles
that alert it pops the next fault. The special fault 'stubborn' is never consumed.

Faults:
  timeout                 agent hangs longer than the orchestrator deadline
  malformed_json          reply is chatty prose instead of JSON
  bad_category            valid JSON but category is outside the allowed enum
  bad_receiver            reply is addressed to a non-existent agent ('validater')
  hallucinated_indicator  evidence contains an indicator not present in the alert
  wrong_category          category contradicts the alert text
  stubborn                always returns bad_category (never recovers)
  ignore_feedback         valid JSON, but ignores every revision request (severity
                          never improves) - exercises the max-iterations guardrail
"""
from __future__ import annotations

PERSISTENT = {"stubborn", "ignore_feedback"}
FAULT_NAMES = {"timeout", "malformed_json", "bad_category", "bad_receiver",
               "hallucinated_indicator", "wrong_category"} | PERSISTENT


class FaultPlan:
    def __init__(self, plan: dict[str, list[str]] | None = None):
        plan = plan or {}
        for alert_id, faults in plan.items():
            unknown = set(faults) - FAULT_NAMES
            if unknown:
                raise ValueError(f"unknown fault(s) for {alert_id}: {sorted(unknown)}")
        self._plan = {k: list(v) for k, v in plan.items()}

    def next(self, alert_id: str) -> str | None:
        queue = self._plan.get(alert_id)
        if not queue:
            return None
        if queue[0] in PERSISTENT:
            return queue[0]
        return queue.pop(0)
