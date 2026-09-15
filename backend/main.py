from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from engines.alert_engine import AlertEngine
from engines.prioritization_engine import (
    PrioritizationEngine
)
from engines.investigation_engine import (
    InvestigationEngine
)
from engines.threat_engine import ThreatEngine
from engines.response_engine import ResponseEngine

from models.environment import (
    SecurityEnvironment
)

from database import (
    initialize_database,
    insert_alert,
    update_alert_status
)


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


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# --------------------------------------------------
# SERVICES
# --------------------------------------------------

alert_engine = AlertEngine()

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


# --------------------------------------------------
# STARTUP
# --------------------------------------------------

@app.on_event("startup")
def startup():

    initialize_database()

    alerts = alert_engine.load_scenarios()

    for alert in alerts:
        insert_alert(alert)


# --------------------------------------------------
# ROOT
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "system": "AI SOC Analyst",
        "status": "ONLINE",
        "version": "1.0.0",
        "description": (
            "Classical AI based SOC "
            "decision-support system."
        )
    }


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


# --------------------------------------------------
# HILL CLIMBING
# --------------------------------------------------

@app.post("/api/prioritize")
def prioritize_alerts():

    alerts = (
        alert_engine.get_all_alerts()
    )

    result = (
        prioritization_engine.prioritize(
            alerts
        )
    )

    return result


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

    result = (
        investigation_engine.investigate(
            alert
        )
    )

    if "error" in result:
        raise HTTPException(
            status_code=400,
            detail=result["error"]
        )

    # Use the IDDFS path for the deeper
    # threat assessment.
    assessment = (
        threat_engine.calculate_score(
            result["iddfs"]["path"]
        )
    )

    alert.status = (
        "CONFIRMED"
        if assessment["classification"]
        == "CONFIRMED"
        else assessment["classification"]
    )

    update_alert_status(
        alert.id,
        alert.status
    )

    return {
        "alert": alert.to_dict(),

        "investigation": result,

        "threat_assessment": assessment
    }


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

    result = response_engine.approve(
        alert
    )

    if result["success"]:

        update_alert_status(
            alert.id,
            alert.status
        )

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

    result = response_engine.reject(
        alert
    )

    if result["success"]:

        update_alert_status(
            alert.id,
            alert.status
        )

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

        score = alert.priority_score()

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