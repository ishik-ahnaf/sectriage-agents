# Message schema

## Example: classifier -> validator (`classification_result`)
```json
{
  "message_id": "2d7a0ea4",
  "conversation_id": "conv-A-002",
  "step": 2,
  "timestamp": "2026-10-17T13:13:51.538+00:00",
  "sender": "classifier",
  "receiver": "validator",
  "intent": "classification_result",
  "content": {
    "alert_id": "A-002",
    "category": "brute_force",
    "severity": "medium",
    "confidence": 0.85,
    "rationale": "Matched 'brute_force' pattern in alert text; indicators: 203.0.113.45.",
    "evidence": {"indicators": ["203.0.113.45"], "metric": "failed_attempts", "count": 57.0},
    "source_text": "sshd[2211]: Failed password for root from 203.0.113.45 port 52144 ssh2 (attempts=57 in 120s)"
  },
  "constraints": {"format": "json"},
  "in_reply_to": "da9808f2"
}
```

## Example: validator -> classifier (`revise_classification`)
```json
{
  "intent": "revise_classification",
  "sender": "validator", "receiver": "classifier",
  "content": {
    "alert_id": "A-002",
    "issues": ["severity 'medium' too low for brute_force (count=57); minimum is 'high'"],
    "required": {"min_severity": "high"},
    "attempt": 1
  },
  "constraints": {"format": "json"}
}
```
(envelope fields abbreviated)

Validation rules are defined in `sectriage/protocol.py` (`INTENT_SCHEMAS`, `ROUTING_POLICY`).
