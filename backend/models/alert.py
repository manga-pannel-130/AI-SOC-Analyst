from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Alert:
    id: str
    alert_type: str
    description: str

    severity: int
    frequency: int
    asset_criticality: int
    business_impact: int
    confidence: int

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    asset_id: Optional[str] = None

    status: str = "NEW"
    source: str = "seed"
    run_id: Optional[str] = None
    created_at: Optional[str] = None
    archived: bool = False
    triage_decision: Optional[str] = None
    simulated_evidence: Optional[List[str]] = None
    threat_classification: Optional[str] = None
    threat_score: Optional[float] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    investigation: Optional[Dict[str, Any]] = None
    response_plan: Optional[Dict[str, Any]] = None
    resolution_action: Optional[str] = None

    def priority_score(self, asset_criticality: Optional[float] = None) -> float:
        """
        Calculate the base priority score for the alert.

        All input factors are expected to be between 0 and 10.
        The final score is normalized to a 0-100 scale.
        """

        criticality = (
            self.asset_criticality
            if asset_criticality is None
            else asset_criticality
        )
        threat_evidence = (self.threat_score or 0) / 10
        score = (
            0.25 * self.severity
            + 0.10 * self.frequency
            + 0.25 * criticality
            + 0.15 * self.business_impact
            + 0.10 * self.confidence
            + 0.15 * threat_evidence
        )

        return round(score * 10, 2)

    def to_dict(self):
        return {
            "id": self.id,
            "alert_type": self.alert_type,
            "description": self.description,
            "severity": self.severity,
            "frequency": self.frequency,
            "asset_criticality": self.asset_criticality,
            "business_impact": self.business_impact,
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "asset_id": self.asset_id,
            "status": self.status,
            "source": self.source,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "archived": self.archived,
            "triage_decision": self.triage_decision,
            "simulated_evidence": self.simulated_evidence or [],
            "threat_classification": self.threat_classification,
            "threat_score": self.threat_score,
            "evidence": self.evidence or [],
            "investigation": self.investigation,
            "response_plan": self.response_plan,
            "resolution_action": self.resolution_action,
            "priority_score": self.priority_score(),
        }