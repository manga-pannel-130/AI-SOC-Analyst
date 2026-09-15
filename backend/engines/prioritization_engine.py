from algorithms.prioritization.hill_climbing import (
    HillClimbingPrioritizer
)


class PrioritizationEngine:

    def prioritize(self, alerts):

        prioritizer = HillClimbingPrioritizer(
            alerts
        )

        (
            optimized_alerts,
            state_score,
            iterations
        ) = prioritizer.optimize()

        return {
            "algorithm": "Hill Climbing",
            "state_score": state_score,
            "iterations": iterations,
            "alerts": [
                {
                    "rank": index,
                    "id": alert.id,
                    "type": alert.alert_type,
                    "priority_score": alert.priority_score(),
                    "severity": alert.severity,
                    "asset_criticality": alert.asset_criticality,
                    "status": alert.status
                }
                for index, alert
                in enumerate(
                    optimized_alerts,
                    start=1
                )
            ]
        }