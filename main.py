#!/usr/bin/env python3
"""SecTriage CLI.

Examples
  python main.py                          # all 9 demo alerts (with fault injection)
  python main.py --alerts A-002 A-007     # just these alerts
  python main.py --no-faults              # same alerts, no injected faults
  python main.py --text "sshd: Failed password for admin from 10.1.1.1 (attempts=90 in 60s)"
  python main.py --brain llm --no-faults  # use the Anthropic API (needs ANTHROPIC_API_KEY)
"""
from __future__ import annotations

import argparse
import json

from sectriage.agents import ClassifierAgent, ValidatorAgent
from sectriage.faults import FaultPlan
from sectriage.logger import CommLog
from sectriage.orchestrator import Orchestrator
from sectriage.scenarios import ALERTS, DEFAULT_FAULTS


def main() -> int:
    p = argparse.ArgumentParser(description="Two-agent security alert triage")
    p.add_argument("--alerts", nargs="*", help="alert ids to run (default: all)")
    p.add_argument("--text", help="classify a single custom alert text instead")
    p.add_argument("--no-faults", action="store_true", help="disable fault injection")
    p.add_argument("--brain", choices=["rules", "llm"], default="rules")
    p.add_argument("--timeout", type=float, default=1.0, help="per-agent timeout (s)")
    p.add_argument("--max-revisions", type=int, default=3)
    p.add_argument("--max-retries", type=int, default=2)
    p.add_argument("--max-steps", type=int, default=20)
    p.add_argument("--log-dir", default="logs")
    p.add_argument("--run-id", default=None)
    p.add_argument("--quiet", action="store_true", help="no console log echo")
    args = p.parse_args()

    comm = CommLog(args.log_dir, run_id=args.run_id, console=not args.quiet)
    if args.text:
        alerts, faults = [{"alert_id": "CUSTOM-1", "source": "cli", "raw": args.text}], {}
    else:
        alerts = [a for a in ALERTS if not args.alerts or a["alert_id"] in args.alerts]
        faults = {} if args.no_faults else DEFAULT_FAULTS

    agents = {"classifier": ClassifierAgent(comm, FaultPlan(faults), brain=args.brain,
                                            hang_seconds=args.timeout * 2.5),
              "validator": ValidatorAgent(comm)}
    orch = Orchestrator(agents, comm, max_steps=args.max_steps, max_revisions=args.max_revisions,
                        max_retries=args.max_retries, agent_timeout_s=args.timeout)

    results = [orch.process_alert(a) for a in alerts]
    print("\n=== SUMMARY ===")
    print(f"{'alert':<9}{'status':<10}{'category':<18}{'severity':<10}{'steps':<6}{'rev':<4}{'retry':<6}note")
    for r in results:
        c = r["classification"]
        note = r.get("fallback_reason") or ", ".join(r.get("notes", []))
        print(f"{r['alert_id']:<9}{r['status']:<10}{c['category']:<18}{c['severity']:<10}"
              f"{r['steps']:<6}{r['revisions']:<4}{r['retries']:<6}{note}")
    out = f"{args.log_dir}/{comm.run_id}-results.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nLogs: {comm.text_path}\n      {comm.jsonl_path}\nResults: {out}")
    comm.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
