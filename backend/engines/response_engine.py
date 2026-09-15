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

        result = self.minimax.minimax()

        action = result[
            "recommended_action"
        ]

        worst_case_damage = result[
            "worst_case_damage"
        ]

        reasoning = (
            "Minimax selected the defensive action "
            "with the lowest worst-case damage "
            "against possible attacker responses."
        )

        recommendation = ResponseRecommendation(
            alert_id=alert.id,
            recommended_action=action,
            worst_case_damage=worst_case_damage,
            reasoning=reasoning,
            alternatives=result["evaluations"]
        )

        self.pending_recommendations[
            alert.id
        ] = recommendation

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