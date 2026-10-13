from algorithms.prioritization.hill_climbing import (
    HillClimbingPrioritizer
)


class PrioritizationEngine:

    FACTOR_WEIGHTS = {
        "severity": 0.25,
        "frequency": 0.10,
        "asset_criticality": 0.25,
        "business_impact": 0.15,
        "confidence": 0.10,
        "threat_evidence": 0.15,
    }

    def prioritize(self, alerts, initial_order=None, environment=None):

        if initial_order:
            requested_ids = list(initial_order)
            if len(requested_ids) != len(set(requested_ids)):
                raise ValueError("Initial alert order contains duplicate IDs.")
            alerts_by_id = {alert.id: alert for alert in alerts}
            unknown_ids = set(requested_ids) - set(alerts_by_id)
            if unknown_ids:
                raise ValueError(
                    "Initial alert order contains unknown IDs: "
                    + ", ".join(sorted(unknown_ids))
                )
            ordered_alerts = [
                alerts_by_id[alert_id]
                for alert_id in requested_ids
            ]
            included = {alert.id for alert in ordered_alerts}
            ordered_alerts.extend(
                alert for alert in alerts if alert.id not in included
            )
            alerts = ordered_alerts

        def asset_score(alert):
            asset = (
                environment.assets.get(alert.asset_id)
                if environment and alert.asset_id
                else None
            )
            if asset is None:
                return alert.asset_criticality
            return environment.effective_criticality(asset)

        prioritizer = HillClimbingPrioritizer(
            alerts,
            priority_function=lambda alert: alert.priority_score(
                asset_score(alert)
            ),
        )

        trace = []
        (
            optimized_alerts,
            state_score,
            iterations
        ) = prioritizer.optimize(trace=trace)

        def factor_breakdown(alert):
            values = {
                "severity": alert.severity,
                "frequency": alert.frequency,
                "asset_criticality": asset_score(alert),
                "business_impact": alert.business_impact,
                "confidence": alert.confidence,
                "threat_evidence": (alert.threat_score or 0) / 10,
            }
            return {
                key: {
                    "value": round(value, 2),
                    "weight": self.FACTOR_WEIGHTS[key],
                    "points": round(value * self.FACTOR_WEIGHTS[key] * 10, 2),
                }
                for key, value in values.items()
            }

        candidate_evaluations = trace[-1]["candidate_evaluations"]
        return {
            "algorithm": "Hill Climbing",
            "state_score": state_score,
            "iterations": iterations,
            "candidate_evaluations": candidate_evaluations,
            "trace_truncated": trace[-1]["trace_truncated"],
            "stop_reason": trace[-1]["stop_reason"],
            "trace": trace,
            "alerts": [
                {
                    "rank": index,
                    "id": alert.id,
                    "type": alert.alert_type,
                    "priority_score": alert.priority_score(asset_score(alert)),
                    "factor_breakdown": factor_breakdown(alert),
                    "severity": alert.severity,
                    "asset_criticality": asset_score(alert),
                    "status": alert.status,
                    "threat_classification": alert.threat_classification,
                    "triage_decision": alert.triage_decision,
                }
                for index, alert
                in enumerate(
                    optimized_alerts,
                    start=1
                )
            ]
        }
