class IDDFSInvestigator:

    def depth_limited_search(
        self,
        graph,
        current,
        goal,
        depth,
        path,
        visited,
        explored_nodes
    ):
        explored_nodes.append(current)

        if current == goal:
            return path

        if depth == 0:
            return None

        for neighbor in graph.get(current, []):

            if neighbor in visited:
                continue

            visited.add(neighbor)

            result = self.depth_limited_search(
                graph=graph,
                current=neighbor,
                goal=goal,
                depth=depth - 1,
                path=path + [neighbor],
                visited=visited,
                explored_nodes=explored_nodes
            )

            if result is not None:
                return result

            visited.remove(neighbor)

        return None

    def search(
        self,
        graph,
        start="Alert",
        goal="Threat Confirmed",
        max_depth=10
    ):
        """
        Iterative Deepening Depth-First Search.

        Repeatedly performs depth-limited DFS
        with increasing depth.
        """

        all_explored_nodes = []

        for depth in range(max_depth + 1):

            explored_nodes = []

            result = self.depth_limited_search(
                graph=graph,
                current=start,
                goal=goal,
                depth=depth,
                path=[start],
                visited={start},
                explored_nodes=explored_nodes
            )

            all_explored_nodes.extend(explored_nodes)

            if result is not None:

                return {
                    "found": True,
                    "path": result,
                    "explored_nodes": all_explored_nodes,
                    "depth": len(result) - 1,
                    "depth_limit": depth
                }

        return {
            "found": False,
            "path": [],
            "explored_nodes": all_explored_nodes,
            "depth": -1,
            "depth_limit": max_depth
        }