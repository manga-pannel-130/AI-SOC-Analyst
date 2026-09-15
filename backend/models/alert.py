from dataclasses import dataclass
from typing import Optional


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

    def priority_score(self) -> float:
        """
        Calculate the base priority score for the alert.

        All input factors are expected to be between 0 and 10.
        The final score is normalized to a 0-100 scale.
        """

        score = (
            0.30 * self.severity
            + 0.15 * self.frequency
            + 0.25 * self.asset_criticality
            + 0.20 * self.business_impact
            + 0.10 * self.confidence
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
            "priority_score": self.priority_score(),
        }