from typing import List, Tuple

from models.alert import Alert


class HillClimbingPrioritizer:

    def __init__(self, alerts: List[Alert]):
        self.alerts = alerts

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
                alert.priority_score()
                * position_weight
            )

        return round(score, 2)

    def generate_neighbors(
        self,
        state: List[Alert]
    ) -> List[List[Alert]]:

        neighbors = []

        for i in range(len(state)):

            for j in range(i + 1, len(state)):

                neighbor = state.copy()

                neighbor[i], neighbor[j] = (
                    neighbor[j],
                    neighbor[i]
                )

                neighbors.append(neighbor)

        return neighbors

    def optimize(
        self
    ) -> Tuple[List[Alert], float, int]:

        current_state = self.alerts.copy()

        current_score = self.evaluate(
            current_state
        )

        iterations = 0

        while True:

            iterations += 1

            neighbors = self.generate_neighbors(
                current_state
            )

            best_neighbor = current_state
            best_score = current_score

            for neighbor in neighbors:

                score = self.evaluate(neighbor)

                if score > best_score:

                    best_neighbor = neighbor
                    best_score = score

            if best_score <= current_score:
                break

            current_state = best_neighbor
            current_score = best_score

        return (
            current_state,
            current_score,
            iterations
        )