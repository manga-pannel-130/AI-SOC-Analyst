from typing import List, Tuple

from models.alert import Alert


class HillClimbingPrioritizer:

    MAX_TRACE_CANDIDATES = 150
    MAX_CANDIDATE_EVALUATIONS = 5000

    def __init__(self, alerts: List[Alert], priority_function=None):
        self.alerts = alerts
        self.priority_function = priority_function or (
            lambda alert: alert.priority_score()
        )

    def evaluate(self, state: List[Alert]) -> float:
        """
        Evaluate the quality of an alert queue.

        Higher priority alerts receive greater weight
        when placed earlier in the queue.
        """

        score = 0.0
        queue_size = len(state)

        for index, alert in enumerate(state):

            position_weight = queue_size - index

            score += (
                self.priority_function(alert)
                * position_weight
            )

        return round(score, 2)

    def optimize(
        self,
        trace=None
    ) -> Tuple[List[Alert], float, int]:

        current_state = self.alerts.copy()

        current_score = self.evaluate(
            current_state
        )

        iterations = 0
        candidate_evaluations = 0
        evaluation_limit_reached = False
        if trace is not None:
            trace.append({
                "type": "start",
                "score": current_score,
                "order": [alert.id for alert in current_state],
            })

        while True:

            iterations += 1

            best_neighbor = current_state
            best_score = current_score
            best_swap = None

            for i, j in (
                (i, j)
                for i in range(len(current_state))
                for j in range(i + 1, len(current_state))
            ):
                if candidate_evaluations >= self.MAX_CANDIDATE_EVALUATIONS:
                    evaluation_limit_reached = True
                    break
                neighbor = current_state.copy()
                neighbor[i], neighbor[j] = neighbor[j], neighbor[i]

                score = self.evaluate(neighbor)

                candidate_evaluations += 1
                if (
                    trace is not None
                    and candidate_evaluations <= self.MAX_TRACE_CANDIDATES
                ):
                    trace.append({
                        "type": "candidate",
                        "swap": [i, j],
                        "score": score,
                        "improves": score > best_score,
                    })

                if score > best_score:

                    best_neighbor = neighbor
                    best_score = score
                    best_swap = [i, j]

            if best_score <= current_score or evaluation_limit_reached:
                if best_score > current_score:
                    current_state = best_neighbor
                    current_score = best_score
                    best_swap = best_swap
                    if trace is not None:
                        trace.append({
                            "type": "move",
                            "swap": best_swap,
                            "score": current_score,
                            "order": [alert.id for alert in current_state],
                        })
                if trace is not None:
                    trace.append({
                        "type": "complete",
                        "score": current_score,
                        "order": [alert.id for alert in current_state],
                        "iterations": iterations,
                        "candidate_evaluations": candidate_evaluations,
                        "captured_candidates": min(
                            candidate_evaluations,
                            self.MAX_TRACE_CANDIDATES,
                        ),
                        "trace_truncated": (
                            candidate_evaluations > self.MAX_TRACE_CANDIDATES
                        ),
                        "stop_reason": "evaluation_limit" if evaluation_limit_reached else "local_optimum",
                    })
                break

            current_state = best_neighbor
            current_score = best_score
            if trace is not None:
                trace.append({
                    "type": "move",
                    "swap": best_swap,
                    "score": current_score,
                    "order": [alert.id for alert in current_state],
                })

        return (
            current_state,
            current_score,
            iterations
        )
