import random
import threading
import uuid
from collections import deque
from dataclasses import fields
from datetime import datetime, timezone
from queue import Empty, Full, Queue

from models.alert import Alert


class SimulationEngine:
    MAX_ACTIVE_SIMULATION_ALERTS = 100
    EVENT_HISTORY_SIZE = 500

    def __init__(
        self,
        alert_engine,
        templates,
        environment=None,
        investigation_engine=None,
        workflow_processor=None,
        persist_alert=None,
        archive_alerts=None,
        archive_alert=None,
        seed=2026,
        interval=20,
    ):
        self.alert_engine = alert_engine
        self.templates = templates
        self.environment = environment
        self.investigation_engine = investigation_engine
        self.workflow_processor = workflow_processor
        self.persist_alert = persist_alert
        self.archive_alerts = archive_alerts
        self.archive_alert = archive_alert
        self.seed = seed
        self.interval = interval
        self.generated_count = 0
        self.run_id = uuid.uuid4().hex[:10]
        self.epoch = 0
        self.running = False
        self.paused = False
        self._random = random.Random(seed)
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._thread = None
        self._subscribers = set()
        self._event_sequence = 0
        self._event_history = deque(maxlen=self.EVENT_HISTORY_SIZE)

    def subscribe(self, last_event_id=None):
        subscriber = Queue(maxsize=100)
        with self._lock:
            self._subscribers.add(subscriber)
            if last_event_id is None:
                subscriber.put({"type": "state", **self._state_event()})
            else:
                oldest = self._event_sequence - len(self._event_history) + 1
                if last_event_id < oldest - 1:
                    subscriber.put({
                        "type": "resync_required",
                        "event_id": self._event_sequence,
                        "state": self._state_event(),
                    })
                else:
                    missed = [
                        event for event in self._event_history
                        if event["event_id"] > last_event_id
                    ]
                    if len(missed) > subscriber.maxsize:
                        subscriber.put({
                            "type": "resync_required",
                            "event_id": self._event_sequence,
                            "state": self._state_event(),
                        })
                    else:
                        for event in missed:
                            subscriber.put_nowait(event)
        return subscriber

    def unsubscribe(self, subscriber):
        with self._lock:
            self._subscribers.discard(subscriber)

    def _publish(self, event):
        with self._lock:
            self._event_sequence += 1
            event = {**event, "event_id": self._event_sequence}
            self._event_history.append(event)
            for subscriber in tuple(self._subscribers):
                try:
                    subscriber.put_nowait(event)
                except Full:
                    while True:
                        try:
                            subscriber.get_nowait()
                        except Empty:
                            break
                    try:
                        subscriber.put_nowait({
                            "type": "resync_required",
                            "event_id": self._event_sequence,
                            "state": self._state_event(),
                        })
                    except Full:
                        continue

    def _state_event(self):
        return {
            "type": "state",
            "running": self.running,
            "paused": self.paused,
            "seed": self.seed,
            "interval": self.interval,
            "generated_count": self.generated_count,
            "epoch": self.epoch,
            "run_id": self.run_id,
        }

    def get_state(self):
        with self._lock:
            return self._state_event()

    def configure(self, interval):
        interval = float(interval)
        if not 2 <= interval <= 30:
            raise ValueError("Arrival interval must be between 2 and 30 seconds.")
        with self._lock:
            self.interval = interval
            self._wake.set()
            event = self._state_event()
        self._publish(event)
        return event

    def start(self):
        with self._lock:
            self.running = True
            self.paused = False
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(
                    target=self._run,
                    name="soc-alert-simulation",
                    daemon=True,
                )
                self._thread.start()
            self._wake.set()
            event = self._state_event()
        self._publish(event)
        return event

    def pause(self):
        with self._lock:
            self.paused = True
            self._wake.set()
            event = self._state_event()
        self._publish(event)
        return event

    def resume(self):
        with self._lock:
            if not self.running:
                return self.start()
            self.paused = False
            self._wake.set()
            event = self._state_event()
        self._publish(event)
        return event

    def stop(self, publish=True):
        with self._lock:
            self.running = False
            self.paused = False
            self._wake.set()
            thread = self._thread
            event = self._state_event()
        if thread and thread is not threading.current_thread():
            thread.join()
            with self._lock:
                if self._thread is thread:
                    self._thread = None
        if publish:
            self._publish(event)
        return event

    def reset(self, seed=None):
        self.stop(publish=False)
        if self.archive_alerts:
            self.archive_alerts()
        with self._lock:
            if seed is not None:
                self.seed = int(seed)
            self._random = random.Random(self.seed)
            self.generated_count = 0
            self.run_id = uuid.uuid4().hex[:10]
            self.epoch += 1
            self.alert_engine.alerts = [
                alert for alert in self.alert_engine.alerts
                if alert.source != "simulation"
            ]
            event = self._state_event()
            event["type"] = "reset"
            for subscriber in tuple(self._subscribers):
                while True:
                    try:
                        subscriber.get_nowait()
                    except Empty:
                        break
        self._publish(event)
        return event

    def _generate_alert(self):
        template = self._random.choice(self.templates)
        self.generated_count += 1
        values = {
            item.name: getattr(template, item.name)
            for item in fields(Alert)
        }
        values["id"] = f"LIVE-{self.run_id}-{self.generated_count:06d}"
        values["description"] = f"Simulated incoming signal: {template.description}"
        values["source"] = "simulation"
        values["run_id"] = self.run_id
        values["created_at"] = datetime.now(timezone.utc).isoformat()
        values["archived"] = False
        values["triage_decision"] = None
        values["simulated_evidence"] = []
        values["threat_classification"] = None
        values["threat_score"] = None
        values["evidence"] = []
        values["investigation"] = None
        values["response_plan"] = None
        values["resolution_action"] = None
        for field in (
            "severity",
            "frequency",
            "asset_criticality",
            "business_impact",
            "confidence",
        ):
            values[field] = max(
                0,
                min(10, getattr(template, field) + self._random.choice((-2, -1, 0, 1, 2))),
            )
        if self.environment:
            candidates = self._asset_candidates(template.alert_type)
            if candidates:
                asset = self._random.choice(candidates)
                values["asset_id"] = asset.asset_id
                values["asset_criticality"] = (
                    self.environment.effective_criticality(asset)
                )
        values["status"] = "NEW"
        alert = Alert(**values)
        if self.investigation_engine:
            alert.simulated_evidence = (
                self.investigation_engine.generate_simulated_evidence(
                    alert,
                    self._random,
                )
            )
        return alert

    def _asset_candidates(self, alert_type):
        asset_types = {
            "BRUTE_FORCE": {"Workstation", "Identity Server"},
            "MALWARE_DETECTION": {"Workstation", "Application Server"},
            "UNAUTHORIZED_USB": {"Workstation"},
            "SUSPICIOUS_PROCESS": {"Workstation", "Application Server"},
            "NETWORK_ANOMALY": {
                "File Server", "Web Server", "Database Server",
                "Application Server", "Network Gateway",
            },
            "IMPOSSIBLE_TRAVEL": {"Workstation", "Identity Server"},
        }.get(alert_type, set())
        return [
            asset
            for asset in self.environment.assets.values()
            if asset.asset_type in asset_types
        ]

    def _run(self):
        while True:
            with self._lock:
                if not self.running:
                    return
                paused = self.paused
            if paused:
                self._wake.wait()
                self._wake.clear()
                continue
            if self._wake.wait(self.interval):
                self._wake.clear()
                continue
            with self._lock:
                if not self.running or self.paused:
                    continue
                try:
                    alert = self._generate_alert()
                    active_simulated = [
                        item for item in self.alert_engine.alerts
                        if item.source == "simulation"
                    ]
                    if len(active_simulated) >= self.MAX_ACTIVE_SIMULATION_ALERTS:
                        oldest = min(
                            active_simulated,
                            key=lambda item: item.created_at or "",
                        )
                        if self.archive_alert:
                            self.archive_alert(oldest.id)
                        oldest.archived = True
                        self.alert_engine.alerts.remove(oldest)
                    if self.persist_alert:
                        self.persist_alert(alert)
                except Exception as error:
                    self._publish({
                        "type": "pipeline_error",
                        "stage": "persistence",
                        "message": str(error),
                    })
                    continue
                self.alert_engine.alerts.append(alert)
                event = {
                    "type": "alert",
                    "alert": alert.to_dict(),
                    "seed": self.seed,
                    "generated_count": self.generated_count,
                    "epoch": self.epoch,
                    "run_id": self.run_id,
                }
            self._publish(event)
            if self.workflow_processor:
                try:
                    self.workflow_processor(alert, self._publish)
                except Exception as error:
                    self._publish({
                        "type": "pipeline_error",
                        "alert_id": alert.id,
                        "stage": "analysis",
                        "message": str(error),
                    })
            self._publish(self.get_state())
