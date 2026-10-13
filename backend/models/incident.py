from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class InvestigationResult:
    alert_id: str
    algorithm: str
    path: List[str]
    explored_nodes: List[str]
    depth: int
    evidence: List[Dict]
    threat_score: float
    classification: str

    def to_dict(self):
        return {
            "alert_id": self.alert_id,
            "algorithm": self.algorithm,
            "path": self.path,
            "explored_nodes": self.explored_nodes,
            "depth": self.depth,
            "evidence": self.evidence,
            "threat_score": self.threat_score,
            "classification": self.classification,
        }


@dataclass
class ResponseRecommendation:
    alert_id: str
    recommended_action: str
    worst_case_damage: float
    reasoning: str
    alternatives: List[Dict] = field(default_factory=list)
    trace: List[Dict] = field(default_factory=list)
    risk_before: float = 0
    estimated_loss_usd: int = 0
    asset_loss_exposure_usd: int = 0
    model_note: str = ""

    def to_dict(self):
        return {
            "alert_id": self.alert_id,
            "recommended_action": self.recommended_action,
            "worst_case_damage": self.worst_case_damage,
            "reasoning": self.reasoning,
            "alternatives": self.alternatives,
            "trace": self.trace,
            "risk_before": self.risk_before,
            "estimated_loss_usd": self.estimated_loss_usd,
            "asset_loss_exposure_usd": self.asset_loss_exposure_usd,
            "model_note": self.model_note,
        }