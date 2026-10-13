from algorithms.response.minimax import (
    MinimaxResponsePlanner
)

from models.incident import (
    ResponseRecommendation
)


class ResponseEngine:

    def __init__(self, environment):

        self.environment = environment

        self.minimax = (
            MinimaxResponsePlanner()
        )

        self.pending_recommendations = {}

    def recommend(
        self,
        alert
    ):

        asset = (
            self.environment.assets.get(alert.asset_id)
            if alert.asset_id
            else None
        )
        result = self.minimax.minimax(alert, asset)

        action = result[
            "recommended_action"
        ]

        worst_case_damage = result[
            "worst_case_damage"
        ]

        reasoning = (
            f"Compared {len(result['evaluations'])} available actions against "
            f"their modeled worst-case attacker responses. "
            f"The lowest modeled damage is {worst_case_damage}/100, "
            f"based on threat score {alert.threat_score or 0}/100 and "
            f"estimated asset exposure ${result['asset_loss_exposure_usd']:,}."
        )

        recommendation = ResponseRecommendation(
            alert_id=alert.id,
            recommended_action=action,
            worst_case_damage=worst_case_damage,
            reasoning=reasoning,
            alternatives=result["evaluations"],
            trace=result["trace"],
            risk_before=result["risk_before"],
            estimated_loss_usd=result["estimated_loss_usd"],
            asset_loss_exposure_usd=result["asset_loss_exposure_usd"],
            model_note=result["model_note"],
        )

        if (
            alert.threat_classification == "CONFIRMED"
            and alert.status == "CONFIRMED"
        ):
            self.pending_recommendations[alert.id] = recommendation
        else:
            self.pending_recommendations.pop(alert.id, None)

        return recommendation

    def approve(
        self,
        alert
    ):

        recommendation = (
            self.pending_recommendations.get(
                alert.id
            )
        )

        if not recommendation:

            return {
                "success": False,
                "message": (
                    "No pending response "
                    "recommendation exists."
                )
            }

        if alert.status != "CONFIRMED":
            self.pending_recommendations.pop(alert.id, None)
            return {
                "success": False,
                "message": "Only a confirmed alert with a pending approval can be responded to.",
            }

        action = recommendation.recommended_action

        if action == "BLOCK_IP":

            self.environment.block_ip(
                alert.source_ip
            )

        elif action == "ISOLATE_ENDPOINT":

            self.environment.isolate_endpoint(
                alert.asset_id
            )

        elif action == "DISABLE_USER":

            self.environment.disable_user(
                alert.username
            )

        elif action == "MONITOR":

            pass

        alert.status = "RESPONDED"

        del self.pending_recommendations[
            alert.id
        ]

        return {
            "success": True,
            "action": action,
            "alert_id": alert.id,
            "message": (
                f"{action} applied successfully "
                "to the simulated environment."
            ),
            "environment": (
                self.environment.get_state()
            )
        }

    def reject(self, alert):

        recommendation = (
            self.pending_recommendations.get(
                alert.id
            )
        )

        if not recommendation:

            return {
                "success": False,
                "message": (
                    "No pending response "
                    "recommendation exists."
                )
            }

        if alert.status != "CONFIRMED":
            self.pending_recommendations.pop(alert.id, None)
            return {
                "success": False,
                "message": "Only a confirmed alert with a pending approval can be rejected.",
            }

        alert.status = "RESPONSE_REJECTED"

        del self.pending_recommendations[
            alert.id
        ]

        return {
            "success": True,
            "alert_id": alert.id,
            "message": (
                "Response rejected by human analyst."
            )
        }
