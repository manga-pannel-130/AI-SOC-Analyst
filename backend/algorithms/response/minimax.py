class MinimaxResponsePlanner:
    def minimax(self, alert, asset=None):
        threat_score = alert.threat_score or 0
        criticality = asset.criticality if asset else alert.asset_criticality
        estimated_loss = asset.estimated_loss_usd if asset else 100000
        risk_before = min(
            100,
            round(
                0.50 * threat_score
                + 0.20 * alert.severity * 10
                + 0.15 * alert.business_impact * 10
                + 0.10 * criticality * 10
                + 0.05 * alert.confidence * 10,
                1,
            ),
        )

        efficacy_by_type = {
            "BLOCK_IP": {
                "BRUTE_FORCE": 0.78,
                "NETWORK_ANOMALY": 0.70,
            },
            "ISOLATE_ENDPOINT": {
                "MALWARE_DETECTION": 0.84,
                "SUSPICIOUS_PROCESS": 0.80,
                "UNAUTHORIZED_USB": 0.76,
            },
            "DISABLE_USER": {
                "BRUTE_FORCE": 0.78,
                "IMPOSSIBLE_TRAVEL": 0.78,
            },
            "MONITOR": {},
        }
        disruption_cost = {
            "BLOCK_IP": 3,
            "ISOLATE_ENDPOINT": round(4 + criticality * 0.55, 1),
            "DISABLE_USER": round(3 + alert.business_impact * 0.4, 1),
            "MONITOR": 0,
        }
        reactions = {
            "BLOCK_IP": [
                ("ATTACKER_ROTATES_SOURCE", 1.15),
                ("ATTACKER_STOPS", 0.12),
            ],
            "ISOLATE_ENDPOINT": [
                ("ATTACKER_ATTEMPTS_LATERAL_MOVEMENT", 1.20),
                ("ENDPOINT_CONTAINED", 0.12),
            ],
            "DISABLE_USER": [
                ("ATTACKER_TRIES_ANOTHER_ACCOUNT", 1.15),
                ("ACCOUNT_ACCESS_STOPPED", 0.12),
            ],
            "MONITOR": [
                ("ATTACK_CONTINUES", 1.0),
                ("ATTACK_ESCALATES", 1.2),
            ],
        }

        available_actions = ["MONITOR"]
        if alert.source_ip:
            available_actions.append("BLOCK_IP")
        if alert.asset_id and asset:
            available_actions.append("ISOLATE_ENDPOINT")
        if alert.username:
            available_actions.append("DISABLE_USER")

        evaluations = []
        trace = []
        type_effectiveness = efficacy_by_type
        for action in available_actions:
            efficacy = type_effectiveness[action].get(alert.alert_type, 0.25)
            remaining_risk = max(0, 1 - efficacy)
            action_cost = disruption_cost[action]
            outcomes = []
            for response, reaction_multiplier in reactions[action]:
                damage = min(
                    100,
                    round(
                        risk_before * remaining_risk * reaction_multiplier
                        + action_cost,
                        1,
                    ),
                )
                outcome = {
                    "response": response,
                    "damage": damage,
                    "estimated_loss_usd": round(estimated_loss * damage / 100),
                }
                outcomes.append(outcome)
                trace.append({
                    "action": action,
                    **outcome,
                    "risk_before": risk_before,
                    "effectiveness": efficacy,
                    "response_cost": action_cost,
                })

            worst_case = max(
                outcomes,
                key=lambda outcome: outcome["damage"],
            )
            evaluations.append({
                "action": action,
                "attacker_responses": outcomes,
                "worst_case_damage": worst_case["damage"],
                "estimated_loss_usd": worst_case["estimated_loss_usd"],
                "effectiveness": efficacy,
                "response_cost": action_cost,
            })

        best_action = min(
            evaluations,
            key=lambda result: result["worst_case_damage"],
        )
        return {
            "recommended_action": best_action["action"],
            "worst_case_damage": best_action["worst_case_damage"],
            "estimated_loss_usd": best_action["estimated_loss_usd"],
            "risk_before": risk_before,
            "asset_loss_exposure_usd": estimated_loss,
            "evaluations": evaluations,
            "trace": trace,
            "model_note": (
                "Illustrative simulated costs and reaction assumptions; "
                "not calibrated from production incidents."
            ),
        }
