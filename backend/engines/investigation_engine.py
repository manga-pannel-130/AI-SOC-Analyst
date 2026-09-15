from algorithms.investigation.bfs import (
    BFSInvestigator
)

from algorithms.investigation.iddfs import (
    IDDFSInvestigator
)

from data.investigation_graphs import (
    INVESTIGATION_GRAPHS
)


class InvestigationEngine:

    def __init__(self):

        self.bfs = BFSInvestigator()
        self.iddfs = IDDFSInvestigator()

    def get_graph(self, alert_type):

        return INVESTIGATION_GRAPHS.get(
            alert_type,
            {}
        )

    def investigate(self, alert):

        graph = self.get_graph(
            alert.alert_type
        )

        if not graph:

            return {
                "error": (
                    f"No investigation graph "
                    f"exists for {alert.alert_type}"
                )
            }

        bfs_result = self.bfs.search(
            graph=graph,
            start="Alert",
            goal="Threat Confirmed"
        )

        # IDDFS is used as the deeper investigation
        # method when BFS has not provided enough
        # investigation depth.
        iddfs_result = self.iddfs.search(
            graph=graph,
            start="Alert",
            goal="Threat Confirmed",
            max_depth=10
        )

        return {
            "alert_id": alert.id,
            "alert_type": alert.alert_type,

            "graph": graph,

            "bfs": bfs_result,

            "iddfs": iddfs_result
        }