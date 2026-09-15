class MinimaxResponsePlanner:

    ACTIONS = [
        "BLOCK_IP",
        "ISOLATE_ENDPOINT",
        "DISABLE_USER",
        "MONITOR"
    ]

    ATTACKER_RESPONSES = {
        "BLOCK_IP": [
            "CHANGE_IP",
            "STOP_ACTIVITY"
        ],

        "ISOLATE_ENDPOINT": [
            "LATERAL_MOVEMENT",
            "STOP_ACTIVITY"
        ],

        "DISABLE_USER": [
            "USE_ANOTHER_ACCOUNT",
            "STOP_ACTIVITY"
        ],

        "MONITOR": [
            "CONTINUE_ATTACK",
            "ESCALATE_ATTACK"
        ]
    }

    def __init__(self):

        self.damage_matrix = {
            "BLOCK_IP": {
                "CHANGE_IP": 65,
                "STOP_ACTIVITY": 15
            },

            "ISOLATE_ENDPOINT": {
                "LATERAL_MOVEMENT": 35,
                "STOP_ACTIVITY": 10
            },

            "DISABLE_USER": {
                "USE_ANOTHER_ACCOUNT": 50,
                "STOP_ACTIVITY": 20
            },

            "MONITOR": {
                "CONTINUE_ATTACK": 90,
                "ESCALATE_ATTACK": 100
            }
        }

    def minimax(self):

        results = []

        for action in self.ACTIONS:

            attacker_outcomes = (
                self.damage_matrix[action]
            )

            worst_case_damage = max(
                attacker_outcomes.values()
            )

            results.append({
                "action": action,
                "attacker_responses": [
                    {
                        "response": response,
                        "damage": damage
                    }
                    for response, damage
                    in attacker_outcomes.items()
                ],
                "worst_case_damage": worst_case_damage
            })

        best_action = min(
            results,
            key=lambda result:
                result["worst_case_damage"]
        )

        return {
            "recommended_action": best_action["action"],
            "worst_case_damage": best_action[
                "worst_case_damage"
            ],
            "evaluations": results
        }