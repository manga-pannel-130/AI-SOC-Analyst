from collections import deque


class BFSInvestigator:

    def search(self, graph, start="Alert", goal="Threat Confirmed"):
        """
        Breadth-First Search.

        Returns the shortest path from the alert
        to the target investigation outcome.
        """

        queue = deque([(start, [start])])
        visited = {start}
        explored_nodes = []
        tree_edges = []

        while queue:

            current, path = queue.popleft()

            explored_nodes.append(current)

            if current == goal:
                return {
                    "found": True,
                    "path": path,
                    "explored_nodes": explored_nodes,
                    "depth": len(path) - 1,
                    "tree_edges": tree_edges,
                    "visit_order": list(explored_nodes),
                }

            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    tree_edges.append({
                        "parent": current,
                        "child": neighbor,
                    })
                    queue.append(
                        (neighbor, path + [neighbor])
                    )

        return {
            "found": False,
            "path": [],
            "explored_nodes": explored_nodes,
            "depth": -1,
            "tree_edges": tree_edges,
            "visit_order": list(explored_nodes),
        }
