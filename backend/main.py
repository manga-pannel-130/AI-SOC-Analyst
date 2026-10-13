import json
import random
import threading
from queue import Empty
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel

from engines.alert_engine import AlertEngine
from engines.prioritization_engine import (
    PrioritizationEngine
)
from engines.investigation_engine import (
    InvestigationEngine
)
from engines.threat_engine import ThreatEngine
from engines.response_engine import ResponseEngine
from engines.simulation_engine import SimulationEngine

from models.environment import (
    SecurityEnvironment
)

from database import (
    initialize_database,
    get_all_alerts,
    get_alert_history,
    insert_alert,
    archive_all_simulation_alerts,
    archive_simulation_alert,
    save_alert_workflow,
    reset_alert_statuses,
)


class PriorityRequest(BaseModel):
    initial_order: Optional[List[str]] = None


class SimulationConfigRequest(BaseModel):
    interval: float


class SimulationResetRequest(BaseModel):
    seed: Optional[int] = None


# --------------------------------------------------
# APPLICATION
# --------------------------------------------------

app = FastAPI(
    title="AI SOC Analyst",
    description=(
        "Classical AI based cybersecurity "
        "decision-support system."
    ),
    version="1.0.0"
)


STATIC_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# --------------------------------------------------
# SERVICES
# --------------------------------------------------

alert_engine = AlertEngine()
scenario_templates = alert_engine.load_scenarios()
workflow_lock = threading.RLock()
prioritization_engine = (
    PrioritizationEngine()
)

investigation_engine = (
    InvestigationEngine()
)

threat_engine = ThreatEngine()

environment = SecurityEnvironment()

response_engine = ResponseEngine(
    environment
)


def process_alert_workflow(alert, publish=None):
    with workflow_lock:
        return _process_alert_workflow_locked(alert, publish)


def _process_alert_workflow_locked(alert, publish=None):
    def emit(event_type, **details):
        if publish:
            publish({
                "type": event_type,
                "alert_id": alert.id,
                **details,
            })

    emit(
        "workflow_started",
        message="Running BFS, threat classification, Minimax, and queue reprioritization.",
    )
    if not alert.simulated_evidence:
        alert.simulated_evidence = (
            investigation_engine.generate_simulated_evidence(
                alert,
                random.Random(alert.id),
            )
        )
    investigation = investigation_engine.investigate(alert)
    if "error" in investigation:
        raise RuntimeError(investigation["error"])
    emit("investigation_complete", investigation=investigation)
    assessment = threat_engine.calculate_score(
        investigation["observed_evidence"]
    )
    emit("classification_complete", assessment=assessment)
    alert.investigation = investigation
    alert.evidence = assessment["evidence"]
    alert.threat_score = assessment["score"]
    alert.threat_classification = assessment["classification"]
    if alert.status not in {"RESPONDED", "RESPONSE_REJECTED"}:
        alert.status = assessment["classification"]
    alert.triage_decision = {
        "CONFIRMED": "PRIORITIZE",
        "SUSPICIOUS": "REVIEW",
        "BENIGN": "LOW_PRIORITY",
    }[assessment["classification"]]

    asset = environment.assets.get(alert.asset_id) if alert.asset_id else None
    if asset:
        alert.asset_criticality = environment.effective_criticality(asset)

    recommendation = response_engine.recommend(alert)
    alert.response_plan = recommendation.to_dict()
    alert.response_plan["eligible_for_approval"] = (
        assessment["classification"] == "CONFIRMED"
        and alert.status == "CONFIRMED"
    )
    if not save_alert_workflow(alert):
        raise RuntimeError(f"Could not persist processed alert {alert.id}.")

    priority = prioritization_engine.prioritize(
        alert_engine.get_all_alerts(),
        initial_order=[item.id for item in alert_engine.get_all_alerts()],
        environment=environment,
    )
    alerts_by_id = {
        item.id: item
        for item in alert_engine.get_all_alerts()
    }
    alert_engine.alerts = [
        alerts_by_id[item["id"]]
        for item in priority["alerts"]
    ]
    emit("priority_complete", priority=priority)

    emit(
        "workflow_complete",
        alert=alert.to_dict(),
        investigation=investigation,
        assessment=assessment,
        response_plan=alert.response_plan,
        priority=priority,
        message=(
            f"{alert.triage_decision.replace('_', ' ').title()} · "
            "response requires analyst approval."
        ),
    )
    return {
        "alert": alert.to_dict(),
        "investigation": investigation,
        "threat_assessment": assessment,
        "response_plan": alert.response_plan,
        "priority": priority,
    }


simulation_engine = SimulationEngine(
    alert_engine,
    scenario_templates,
    environment=environment,
    investigation_engine=investigation_engine,
    workflow_processor=process_alert_workflow,
    persist_alert=insert_alert,
    archive_alerts=archive_all_simulation_alerts,
    archive_alert=archive_simulation_alert,
    interval=20,
)


# --------------------------------------------------
# STARTUP
# --------------------------------------------------

@app.on_event("startup")
def startup():

    initialize_database()

    for alert in scenario_templates:
        insert_alert(alert)

    # SQLite is authoritative: keep analyst status across application restarts.
    alert_engine.alerts = get_all_alerts()
    environment.reset()
    for alert in alert_engine.alerts:
        if alert.status != "RESPONDED":
            continue
        if alert.resolution_action == "BLOCK_IP" and alert.source_ip:
            environment.block_ip(alert.source_ip)
        elif alert.resolution_action == "ISOLATE_ENDPOINT" and alert.asset_id:
            environment.isolate_endpoint(alert.asset_id)
        elif alert.resolution_action == "DISABLE_USER" and alert.username:
            environment.disable_user(alert.username)
    random.Random(2026).shuffle(alert_engine.alerts)
    for alert in alert_engine.alerts:
        process_alert_workflow(alert)


@app.on_event("shutdown")
def shutdown():
    simulation_engine.stop(publish=False)


# --------------------------------------------------
# ROOT
# --------------------------------------------------

@app.get("/")
def root():
    return FileResponse(STATIC_DIR / "index.html")


# --------------------------------------------------
# ALERTS
# --------------------------------------------------

@app.get("/api/alerts")
def get_alerts():

    alerts = alert_engine.get_all_alerts()

    return {
        "count": len(alerts),
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ]
    }


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):

    alert = alert_engine.get_alert(
        alert_id
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    return alert.to_dict()


@app.get("/api/history")
def alert_history(limit: int = 20):
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="History limit must be between 1 and 100.")
    alerts = get_alert_history(limit)
    return {
        "count": len(alerts),
        "alerts": [alert.to_dict() for alert in alerts],
    }


# --------------------------------------------------
# HILL CLIMBING
# --------------------------------------------------

@app.post("/api/prioritize")
def prioritize_alerts(payload: Optional[PriorityRequest] = None):

    alerts = (
        alert_engine.get_all_alerts()
    )
    initial_order = payload.initial_order if payload else None

    try:
        result = prioritization_engine.prioritize(
            alerts,
            initial_order=initial_order,
            environment=environment,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    return result


@app.get("/api/events")
def simulation_events(request: Request):
    last_event_id = request.headers.get("last-event-id")
    try:
        last_sequence = int(last_event_id) if last_event_id else None
    except ValueError:
        last_sequence = None
    subscriber = simulation_engine.subscribe(last_sequence)

    def stream():
        try:
            while True:
                try:
                    event = subscriber.get(timeout=15)
                except Empty:
                    yield ": keep-alive\n\n"
                    continue
                event_id = event.get("event_id")
                prefix = f"id: {event_id}\n" if event_id is not None else ""
                yield f"{prefix}data: {json.dumps(event)}\n\n"
        finally:
            simulation_engine.unsubscribe(subscriber)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/simulation")
def get_simulation_state():
    return simulation_engine.get_state()


@app.post("/api/simulation/start")
def start_simulation():
    return simulation_engine.start()


@app.post("/api/simulation/pause")
def pause_simulation():
    return simulation_engine.pause()


@app.post("/api/simulation/resume")
def resume_simulation():
    return simulation_engine.resume()


@app.post("/api/simulation/configure")
def configure_simulation(payload: SimulationConfigRequest):
    try:
        return simulation_engine.configure(payload.interval)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.post("/api/simulation/reset")
def reset_simulation(payload: Optional[SimulationResetRequest] = None):
    seed = payload.seed if payload else None
    simulation_engine.stop(publish=False)
    archive_all_simulation_alerts()
    reset_alert_statuses()
    environment.reset()
    response_engine.pending_recommendations.clear()
    alert_engine.alerts = get_all_alerts()
    state = simulation_engine.reset(seed=seed)
    random.Random(2026).shuffle(alert_engine.alerts)
    for alert in alert_engine.alerts:
        process_alert_workflow(alert)
    return state


# --------------------------------------------------
# INVESTIGATION
# --------------------------------------------------

@app.post("/api/investigate/{alert_id}")
def investigate_alert(
    alert_id: str
):

    alert = alert_engine.get_alert(
        alert_id
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    try:
        result = process_alert_workflow(alert)
    except RuntimeError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        ) from error

    return result


# --------------------------------------------------
# RESPONSE RECOMMENDATION
# --------------------------------------------------

@app.post(
    "/api/recommend-response/{alert_id}"
)
def recommend_response(
    alert_id: str
):

    alert = alert_engine.get_alert(
        alert_id
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    if alert.status != "CONFIRMED":

        raise HTTPException(
            status_code=400,
            detail=(
                "Response recommendation requires "
                "a confirmed threat."
            )
        )

    recommendation = (
        response_engine.recommend(
            alert
        )
    )

    return recommendation.to_dict()


# --------------------------------------------------
# HUMAN APPROVAL
# --------------------------------------------------

@app.post(
    "/api/approve-response/{alert_id}"
)
def approve_response(
    alert_id: str
):

    alert = alert_engine.get_alert(
        alert_id
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    if (
        alert.status != "CONFIRMED"
        or not alert.response_plan
        or not alert.response_plan.get("eligible_for_approval")
    ):
        raise HTTPException(
            status_code=409,
            detail="Only a confirmed alert with an eligible response plan can be approved.",
        )

    result = response_engine.approve(
        alert
    )

    if result["success"]:

        alert.resolution_action = result["action"]
        save_alert_workflow(alert)

    return result


# --------------------------------------------------
# HUMAN REJECTION
# --------------------------------------------------

@app.post(
    "/api/reject-response/{alert_id}"
)
def reject_response(
    alert_id: str
):

    alert = alert_engine.get_alert(
        alert_id
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    if (
        alert.status != "CONFIRMED"
        or not alert.response_plan
        or not alert.response_plan.get("eligible_for_approval")
    ):
        raise HTTPException(
            status_code=409,
            detail="Only a confirmed alert with an eligible response plan can be rejected.",
        )

    result = response_engine.reject(
        alert
    )

    if result["success"]:

        save_alert_workflow(alert)

    return result


# --------------------------------------------------
# SIMULATED ENVIRONMENT
# --------------------------------------------------

@app.get("/api/environment")
def get_environment():

    return environment.get_state()


# --------------------------------------------------
# DASHBOARD SUMMARY
# --------------------------------------------------

@app.get("/api/dashboard")
def dashboard_summary():

    alerts = (
        alert_engine.get_all_alerts()
    )

    critical = 0
    high = 0
    medium = 0
    low = 0

    for alert in alerts:

        asset = environment.assets.get(alert.asset_id) if alert.asset_id else None
        criticality = (
            environment.effective_criticality(asset)
            if asset
            else alert.asset_criticality
        )
        score = alert.priority_score(criticality)

        if score >= 80:
            critical += 1

        elif score >= 60:
            high += 1

        elif score >= 40:
            medium += 1

        else:
            low += 1

    return {
        "total_alerts": len(alerts),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "environment": (
            environment.get_state()
        )
    }
