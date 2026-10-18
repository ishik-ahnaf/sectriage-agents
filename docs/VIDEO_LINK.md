# Demonstration video script (target 4:00 - limit is 3-5 minutes)

Record your screen with a terminal (large font) and the repo open in an editor. Speak in your own words;
the bullets are prompts, not a script to read out.

**0:00-0:30  Intro**
- Your name, unit COIT12204, Assessment 4. One sentence: "SecTriage has a Classifier agent, a Validator agent and an orchestrator."
- Show the architecture diagram in the README.

**0:30-1:15  Agents + message schema**
- Open `sectriage/agents/classifier.py` and `validator.py` briefly: role of each.
- Open `sectriage/protocol.py`: point at the envelope, `INTENT_SCHEMAS` and `ROUTING_POLICY`.

**1:15-2:15  Agents communicating + routing (normal + revision)**
- Run `python main.py --alerts A-001 A-002`
- Point at log lines: orchestrator ROUTED -> classifier RECEIVED/SENT -> validator RECEIVED/SENT.
- For A-002 show the validator's REVISION_ROUND message ("severity 'medium' too low ... minimum is 'high'") and the final `high`.

**2:15-3:30  Failure cases**
- Run `python main.py --alerts A-003 A-005 A-007 A-009`
- A-003: TIMEOUT -> RETRY -> STALE_REPLY_DROPPED -> approved.
- A-005: ROUTE_ERROR (`validater`) -> route_error -> corrected.
- A-007: three INVALID_OUTPUT -> FALLBACK. A-009: MAX_ITERATIONS -> FALLBACK.

**3:30-4:15  Final output + logs**
- Show the SUMMARY table, then open `logs/<run>.jsonl` (or `.log`).
- Run `python -m unittest discover -s tests` -> "OK".

**4:15-4:45  Wrap-up**
- Two improvements you made after debugging; one future improvement; AI declaration in one sentence.
