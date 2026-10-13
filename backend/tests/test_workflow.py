import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import database
from algorithms.prioritization.hill_climbing import HillClimbingPrioritizer
from engines.alert_engine import AlertEngine
from engines.investigation_engine import InvestigationEngine
from engines.simulation_engine import SimulationEngine
from engines.threat_engine import ThreatEngine
from engines.response_engine import ResponseEngine
from models.environment import SecurityEnvironment
from algorithms.response.minimax import MinimaxResponsePlanner


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "alerts.sqlite3"
        self.db_patch = patch.object(database, "DATABASE_PATH", self.db_path)
        self.db_patch.start()
        database.initialize_database()
        self.alerts = AlertEngine().load_scenarios()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_all_seed_scenarios_produce_evidence_and_classification(self):
        investigator = InvestigationEngine()
        threat_engine = ThreatEngine()
        for alert in self.alerts:
            with self.subTest(alert=alert.id):
                investigation = investigator.investigate(alert)
                assessment = threat_engine.calculate_score(
                    investigation["observed_evidence"]
                )
                self.assertTrue(investigation["evidence_paths"])
                self.assertEqual("CONFIRMED", assessment["classification"])
                self.assertGreaterEqual(assessment["score"], 60)
                for trace in investigation["evidence_paths"]:
                    self.assertTrue(trace["bfs"]["found"])
                    self.assertEqual(trace["bfs"]["path"][0], "Alert")
                    self.assertEqual(trace["bfs"]["path"][-1], trace["node"])
                    self.assertEqual(trace["bfs"]["visit_order"], trace["bfs"]["explored_nodes"])

    def test_seed_loading_does_not_reset_persisted_status(self):
        first = self.alerts[0]
        database.insert_alert(first)
        database.update_alert_status(first.id, "CONFIRMED")

        # The same seed set is loaded again on restart, but IDs are inserted
        # only when missing and the existing analyst state remains intact.
        for alert in self.alerts:
            database.insert_alert(alert)
        stored = {alert.id: alert for alert in database.get_all_alerts()}
        self.assertEqual("CONFIRMED", stored[first.id].status)
        self.assertEqual(len(self.alerts), len(stored))

    def test_hill_climbing_returns_priority_order_without_mutating_input(self):
        original = self.alerts.copy()
        trace = []
        ranked, score, iterations = HillClimbingPrioritizer(self.alerts).optimize(trace=trace)
        scores = [alert.priority_score() for alert in ranked]
        self.assertEqual(sorted(scores, reverse=True), scores)
        self.assertEqual(original, self.alerts)
        self.assertGreater(score, 0)
        self.assertGreater(iterations, 0)
        self.assertEqual("start", trace[0]["type"])
        self.assertEqual("complete", trace[-1]["type"])
        self.assertTrue(any(step["type"] == "candidate" for step in trace))

    def test_simulation_pause_and_seeded_reset(self):
        alert_engine = AlertEngine()
        templates = alert_engine.load_scenarios()
        alert_engine.alerts = list(templates)
        simulator = SimulationEngine(
            alert_engine,
            templates,
            seed=84,
            interval=0.01,
        )
        subscriber = simulator.subscribe()

        def next_alert():
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                event = subscriber.get(timeout=0.1)
                if event["type"] == "alert":
                    return event["alert"]
            self.fail("Timed out waiting for a simulated alert.")

        try:
            self.assertTrue(simulator.start()["running"])
            first = next_alert()
            self.assertTrue(first["id"].startswith("LIVE-"))
            self.assertIn(first["alert_type"], {alert.alert_type for alert in templates})
            self.assertTrue(simulator.pause()["paused"])
            count_at_pause = simulator.get_state()["generated_count"]
            time.sleep(0.04)
            self.assertEqual(count_at_pause, simulator.get_state()["generated_count"])
            resumed = simulator.resume()
            self.assertTrue(resumed["running"])
            self.assertFalse(resumed["paused"])
            self.assertTrue(next_alert()["id"].endswith("000002"))
            simulator.pause()

            reset = simulator.reset(seed=84)
            self.assertEqual(0, reset["generated_count"])
            self.assertFalse(reset["running"])
            self.assertEqual(1, reset["epoch"])
            self.assertFalse(any(alert.id.startswith("LIVE-") for alert in alert_engine.alerts))
            with self.assertRaises(ValueError):
                simulator.configure(31)
            simulator.start()
            repeated = next_alert()
            self.assertEqual(first["alert_type"], repeated["alert_type"])
            self.assertEqual(first["asset_id"], repeated["asset_id"])
            self.assertEqual(first["severity"], repeated["severity"])
            self.assertEqual(first["frequency"], repeated["frequency"])
            self.assertEqual(first["source"], repeated["source"])
            self.assertTrue(repeated["id"].startswith("LIVE-"))
            self.assertNotEqual(first["id"], repeated["id"])
        finally:
            simulator.stop()
            simulator.unsubscribe(subscriber)

    def test_minimax_exposes_each_action_evaluation(self):
        alert = self.alerts[0]
        alert.threat_score = 82
        alert.asset_id = "WEB-SERVER-01"
        alert.source_ip = "203.0.113.44"
        alert.username = "svc-alert"
        asset = type("Asset", (), {})()
        asset.asset_id = "WEB-SERVER-01"
        asset.hostname = "web-server-01"
        asset.asset_type = "Web Server"
        asset.criticality = 9
        asset.estimated_loss_usd = 420000
        asset.status = "ONLINE"
        result = MinimaxResponsePlanner().minimax(alert, asset)
        self.assertGreaterEqual(len(result["evaluations"]), 2)
        self.assertGreaterEqual(len(result["trace"]), 2)
        self.assertEqual(
            result["recommended_action"],
            min(result["evaluations"], key=lambda step: step["worst_case_damage"])["action"],
        )

    def test_hill_climbing_rejects_invalid_initial_order(self):
        from engines.prioritization_engine import PrioritizationEngine

        engine = PrioritizationEngine()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            engine.prioritize(self.alerts, initial_order=[self.alerts[0].id] * 2)
        with self.assertRaisesRegex(ValueError, "unknown"):
            engine.prioritize(self.alerts, initial_order=["missing-alert"])

    def test_hill_climbing_stops_at_candidate_evaluation_limit(self):
        trace = []
        with patch.object(HillClimbingPrioritizer, "MAX_CANDIDATE_EVALUATIONS", 2):
            HillClimbingPrioritizer(self.alerts).optimize(trace=trace)
        self.assertEqual(2, trace[-1]["candidate_evaluations"])
        self.assertEqual("evaluation_limit", trace[-1]["stop_reason"])

    def test_response_requires_confirmed_pending_plan_and_is_single_use(self):
        environment = SecurityEnvironment()
        engine = ResponseEngine(environment)
        alert = self.alerts[0]
        alert.status = "CONFIRMED"
        alert.threat_classification = "CONFIRMED"
        alert.threat_score = 80
        plan = engine.recommend(alert)
        self.assertIn(alert.id, engine.pending_recommendations)
        self.assertTrue(plan.recommended_action)
        alert.status = "SUSPICIOUS"
        denied = engine.approve(alert)
        self.assertFalse(denied["success"])
        self.assertNotIn(alert.id, engine.pending_recommendations)
        alert.status = "CONFIRMED"
        engine.recommend(alert)
        approved = engine.approve(alert)
        self.assertTrue(approved["success"])
        self.assertEqual("RESPONDED", alert.status)
        self.assertFalse(engine.approve(alert)["success"])

    def test_sse_replay_reports_gap_when_subscriber_queue_is_too_small(self):
        simulator = SimulationEngine(AlertEngine(), [], interval=20)
        for index in range(120):
            simulator._publish({"type": "probe", "index": index})
        subscriber = simulator.subscribe(last_event_id=0)
        try:
            received = [subscriber.get_nowait() for _ in range(subscriber.qsize())]
            self.assertEqual(1, len(received))
            self.assertEqual("resync_required", received[0]["type"])
        finally:
            simulator.unsubscribe(subscriber)


if __name__ == "__main__":
    unittest.main()
