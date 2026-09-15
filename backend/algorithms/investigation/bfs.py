from collections import deque


class BFSInvestigator:

    def search(self, graph, start="Alert", goal="Threat Confirmed"):
        """
        Breadth-First Search.

        Returns the shortest path from the alert
        to the target investigation outcome.
        """

        queue = deque([
            (start, [start])
        ])

        visited = set()
        explored_nodes = []

        while queue:

            current, path = queue.popleft()

            if current in visited:
                continue

            visited.add(current)
            explored_nodes.append(current)

            if current == goal:
                return {
                    "found": True,
                    "path": path,
                    "explored_nodes": explored_nodes,
                    "depth": len(path) - 1
                }

            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    queue.append(
                        (neighbor, path + [neighbor])
                    )

        return {
            "found": False,
            "path": [],
            "explored_nodes": explored_nodes,
            "depth": -1
        }