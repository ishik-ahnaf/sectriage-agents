"""Run with:  python -m unittest discover -s tests -v"""
import json
import tempfile
import time
import unittest

from sectriage.agents import ClassifierAgent, ValidatorAgent
from sectriage.agents.validator import severity_floor
from sectriage.faults import FaultPlan
from sectriage.logger import CommLog
from sectriage.orchestrator import Orchestrator
from sectriage.protocol import (Message, ProtocolError, check_routing_policy, parse_message,
                                validate_message)
from sectriage.scenarios import ALERTS


def good_result(**over):
    content = {"alert_id": "A-1", "category": "phishing", "severity": "high", "confidence": 0.9,
               "rationale": "Matched phishing pattern in alert text.", "evidence": {"indicators": []},
               "source_text": "verify your password"}
    content.update(over)
    return Message("classifier", "validator", "classification_result", content,
                   conversation_id="conv-A-1").to_dict()


class ProtocolTests(unittest.TestCase):
    def test_valid_message_parses(self):
        self.assertEqual(parse_message(good_result()).intent, "classification_result")

    def test_missing_field_rejected(self):
        raw = good_result()
        del raw["content"]["rationale"]
        self.assertIn("content.rationale is required", validate_message(raw))

    def test_enum_and_range_rejected(self):
        issues = validate_message(good_result(category="ransomware_v2", confidence=1.7))
        self.assertTrue(any("not in" in i for i in issues))
        self.assertTrue(any("above maximum" in i for i in issues))

    def test_non_json_rejected(self):
        with self.assertRaises(ProtocolError):
            parse_message("Sure! Here is my analysis")

    def test_bool_is_not_a_number(self):
        self.assertTrue(validate_message(good_result(confidence=True)))

    def test_routing_policy(self):
        bad = Message("classifier", "orchestrator", "classification_result", {})
        self.assertTrue(check_routing_policy(bad))


class ValidatorRuleTests(unittest.TestCase):
    def test_floors(self):
        self.assertEqual(severity_floor("brute_force", {"count": 57}), "high")
        self.assertEqual(severity_floor("brute_force", {"count": 5}), "low")
        self.assertEqual(severity_floor("malware", {}), "high")


class SystemTests(unittest.TestCase):
    def tearDown(self):
        if hasattr(self, "comm"):
            self.comm.close()

    def build(self, faults=None, **kw):
        self.tmp = tempfile.mkdtemp()
        self.comm = CommLog(self.tmp, run_id="t", console=False)
        agents = {"classifier": ClassifierAgent(self.comm, FaultPlan(faults or {}), hang_seconds=1.0),
                  "validator": ValidatorAgent(self.comm)}
        return Orchestrator(agents, self.comm, agent_timeout_s=0.3, **kw)

    def alert(self, alert_id):
        return next(a for a in ALERTS if a["alert_id"] == alert_id)

    def test_happy_path(self):
        r = self.build().process_alert(self.alert("A-001"))
        self.assertEqual((r["status"], r["steps"], r["revisions"]), ("approved", 3, 0))

    def test_revision_loop_fixes_under_triage(self):
        r = self.build().process_alert(self.alert("A-002"))
        self.assertEqual(r["status"], "approved")
        self.assertEqual((r["classification"]["severity"], r["revisions"]), ("high", 1))

    def test_timeout_then_retry_succeeds(self):
        r = self.build({"A-003": ["timeout"]}).process_alert(self.alert("A-003"))
        self.assertEqual((r["status"], r["retries"]), ("approved", 1))

    def test_no_stale_reply_after_timeout(self):
        orch = self.build({"A-003": ["timeout"]})
        orch.process_alert(self.alert("A-003"))
        time.sleep(1.2)  # longer than the hang
        with open(self.comm.jsonl_path, encoding="utf-8") as fh:
            text = fh.read()
        sent = [json.loads(l) for l in text.splitlines() if '"SENT"' in l]
        self.assertEqual(len(sent), 2)  # classifier + validator only, nothing late
        self.assertIn("STALE_REPLY_DROPPED", text)

    def test_malformed_json_recovered(self):
        r = self.build({"A-004": ["malformed_json"]}).process_alert(self.alert("A-004"))
        self.assertEqual((r["status"], r["retries"]), ("approved", 1))

    def test_invalid_receiver_recovered(self):
        r = self.build({"A-005": ["bad_receiver"]}).process_alert(self.alert("A-005"))
        self.assertEqual(r["status"], "approved")
        self.assertIn("orchestrator->classifier:route_error", r["trace"])

    def test_hallucinated_indicator_caught(self):
        r = self.build({"A-006": ["hallucinated_indicator"]}).process_alert(self.alert("A-006"))
        self.assertEqual(r["status"], "approved")
        self.assertNotIn("198.51.100.200", r["classification"]["evidence"]["indicators"])

    def test_stubborn_invalid_output_falls_back(self):
        r = self.build({"A-007": ["stubborn"]}).process_alert(self.alert("A-007"))
        self.assertEqual((r["status"], r["fallback_reason"]),
                         ("fallback", "invalid_output_retries_exhausted"))

    def test_max_iterations_falls_back(self):
        r = self.build({"A-009": ["ignore_feedback"]}, max_revisions=3).process_alert(self.alert("A-009"))
        self.assertEqual((r["status"], r["fallback_reason"], r["revisions"]),
                         ("fallback", "max_iterations_exceeded", 3))

    def test_max_steps_guardrail(self):
        r = self.build({"A-009": ["ignore_feedback"]}, max_steps=4).process_alert(self.alert("A-009"))
        self.assertEqual(r["fallback_reason"], "max_steps_exceeded")


if __name__ == "__main__":
    unittest.main()
