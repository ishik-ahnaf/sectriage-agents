# SecTriage - a two-agent security alert triage system

COIT12204 AI-Assisted Software Development - Assessment 4 (Individual Practical Application of Dual Agent Systems)

A **Classifier Agent** turns a raw security alert into a structured classification, a
**Validator Agent** independently reviews it, and an **Orchestrator** routes every message,
enforces guardrails and logs everything. If the Validator rejects a result, it sends specific
feedback back to the Classifier (a worker-reviewer loop supervised by the Orchestrator).

```
            classify_alert            classification_result
 alert ──▶ ORCHESTRATOR ───────▶ CLASSIFIER ─────────────▶ (ORCHESTRATOR validates + routes) ──▶ VALIDATOR
              ▲                       ▲                                                             │
              │ validation_result     └──────────── revise_classification (feedback) ◀──────────────┤
              └─────────────────────────────────────────────────────────────────────────────────────┘
```
Every hop passes through the orchestrator - agents never talk to each other directly.

## Setup (Windows / macOS / Linux)

Requires Python 3.10 or newer. No third-party packages are needed.

```bash
git clone <your-repo-url> sectriage-agents
cd sectriage-agents
python --version            # use python3 on macOS/Linux if needed
python main.py              # runs all 9 demo alerts, with fault injection
```

## Useful commands

| Command | What it shows |
|---|---|
| `python main.py` | All 9 alerts incl. injected failures; summary table at the end |
| `python main.py --alerts A-002` | Revision loop (under-triaged brute force corrected by the Validator) |
| `python main.py --alerts A-003` | Timeout -> retry -> stale reply dropped |
| `python main.py --alerts A-005` | Invalid receiver -> `route_error` -> self-correction |
| `python main.py --alerts A-007 A-009` | The two fallbacks (invalid-output retries exhausted; max iterations) |
| `python main.py --no-faults` | Same alerts with no injected faults |
| `python main.py --text "sshd: Failed password for admin from 10.1.1.1 (attempts=90 in 60s)"` | Your own alert |
| `python main.py --timeout 0.5 --max-revisions 2 --max-retries 1` | Tune guardrails |
| `python -m unittest discover -s tests -v` | 17 automated tests |

Logs are written to `logs/<run-id>.log` (human-readable), `logs/<run-id>.jsonl` (structured) and
`logs/<run-id>-results.json` (final decisions). Use `--run-id NAME` to name a run.

## Project layout

```
main.py                      CLI entry point
sectriage/protocol.py        Message envelope, per-intent schemas, routing policy, validation
sectriage/orchestrator.py    Routing, step tracking, max steps/iterations, retries, fallback
sectriage/resilience.py      Timeout wrapper with cooperative cancellation
sectriage/logger.py          Text + JSONL communication log
sectriage/faults.py          Fault injection used to demonstrate/test failure handling
sectriage/scenarios.py       9 demo alerts and the fault plan
sectriage/agents/            base.py, classifier.py, validator.py
tests/test_system.py         Unit + integration tests
docs/                        Message schema, video script, sample logs from the build
```

## Message schema (summary)

Envelope (all messages): `message_id, conversation_id, step, timestamp, sender, receiver, intent,
content, constraints{format:"json"}, in_reply_to`. Content is validated per intent:

| intent | sender -> receiver | content fields |
|---|---|---|
| `classify_alert` | orchestrator -> classifier | alert_id, raw, source? |
| `classification_result` | classifier -> validator | alert_id, category, severity, confidence (0-1), rationale, evidence, source_text |
| `revise_classification` | validator -> classifier | alert_id, issues[], required{min_severity?, suggested_category?, grounded_only?}, attempt |
| `validation_result` | validator -> orchestrator | alert_id, verdict, issues[], classification |
| `route_error` | orchestrator -> sender | alert_id, reason, bad_receiver, original_intent |

Allowed categories: brute_force, phishing, malware, port_scan, data_exfiltration, benign, unknown.
Severities: low, medium, high, critical. Full example in `docs/MESSAGE_SCHEMA.md`.

## Guardrails and where they live

| Mechanism | Default | Code |
|---|---|---|
| Schema + JSON validation of every message | always | `protocol.parse_message` |
| Unknown receiver handling (`route_error` back to sender) | max 2 per alert | `Orchestrator._route_error` |
| Routing policy (who may send which intent to whom) | always | `protocol.check_routing_policy` |
| Sender-spoofing check | always | `Orchestrator._call_agent` |
| Agent timeout + cooperative cancellation | 1.0 s | `resilience.run_with_timeout` |
| Retries on timeout / crash / invalid output | 2 | `Orchestrator._call_agent` |
| Max revision rounds | 3 | `Orchestrator.process_alert` |
| Max routed steps per conversation | 20 | `Orchestrator.process_alert` |
| Fallback to `needs_human_review` | on any unrecoverable error | `Orchestrator._fallback` |
| Error + event logging | always | `logger.CommLog` |

## Optional: LLM brain

`python main.py --brain llm --no-faults` makes the Classifier call the Anthropic API instead of
regex rules (`pip install anthropic`, set `ANTHROPIC_API_KEY`, optionally `ANTHROPIC_MODEL`).
The protocol, Validator and Orchestrator are unchanged - this is what the guardrails are for,
because an LLM can return chatty text, invented indicators or an invalid category.
Note: the default `rules` brain is what the included logs and tests were produced with.

## AI assistance declaration

I used Claude (Anthropic) during this assessment to help structure the project and codes, and to draft the technical report.
The system and all the tests were executed on my personal computer, while the screen captures in this report were taken based
on those executions. Also, the demonstration video has been recorded based on the execution of the test cases by myself. The
snippets shown in this report are taken from my personal execution, logs/run-20261018-161345.log.
