from algorithms.investigation.bfs import BFSInvestigator
from data.investigation_graphs import INVESTIGATION_GRAPHS


# Deterministic observations make this a reproducible lab simulation. These
# values are sample telemetry, not live threat intelligence.
OBSERVED_EVIDENCE = {
    "BRUTE_FORCE": ["Known Malicious IP", "Previous Failed Logins", "Login Frequency"],
    "MALWARE_DETECTION": ["Known Malicious Hash", "Suspicious Parent Process", "Previous Malware Alerts"],
    "UNAUTHORIZED_USB": ["Unauthorized Device", "Previous USB Events", "Sensitive File Access"],
    "SUSPICIOUS_PROCESS": ["Known Malicious Process", "Suspicious Parent Process"],
    "NETWORK_ANOMALY": ["Abnormal Volume", "Suspicious Destination", "Previous Traffic Pattern"],
    "IMPOSSIBLE_TRAVEL": ["Impossible Distance", "Recent Login", "Unknown Device"],
}

EVIDENCE_PROFILES = {
    "BRUTE_FORCE": {
        "malicious": ["Known Malicious IP", "Previous Failed Logins", "Login Frequency"],
        "suspicious": ["Previous Failed Logins", "Login Frequency", "Login Time Anomaly"],
        "benign": ["Known Good IP", "Successful MFA", "Expected Business Hours Login"],
    },
    "MALWARE_DETECTION": {
        "malicious": ["Known Malicious Hash", "Suspicious Parent Process", "Previous Malware Alerts"],
        "suspicious": ["Unknown File Hash", "Suspicious Parent Process"],
        "benign": ["Signed Publisher", "Approved Software", "Clean History"],
    },
    "UNAUTHORIZED_USB": {
        "malicious": ["Unauthorized Device", "Previous USB Events", "Sensitive File Access"],
        "suspicious": ["Unauthorized Device", "Previous USB Events"],
        "benign": ["Authorized Device", "Approved Maintenance Window"],
    },
    "SUSPICIOUS_PROCESS": {
        "malicious": ["Known Malicious Process", "Suspicious Parent Process", "Encoded Command"],
        "suspicious": ["Unknown Process", "Encoded Command"],
        "benign": ["Signed Admin Script", "Approved Change Window", "Normal Command"],
    },
    "NETWORK_ANOMALY": {
        "malicious": ["Abnormal Volume", "Suspicious Destination", "Previous Traffic Pattern"],
        "suspicious": ["Abnormal Volume", "Previous Traffic Pattern"],
        "benign": ["Known Safe Destination", "Scheduled Backup", "Expected Traffic Pattern"],
    },
    "IMPOSSIBLE_TRAVEL": {
        "malicious": ["Impossible Distance", "Recent Login", "Unknown Device"],
        "suspicious": ["Impossible Distance", "Recent Login"],
        "benign": ["Known VPN Exit Node", "Successful MFA", "Known Device"],
    },
}

EVIDENCE_PARENTS = {
    "BRUTE_FORCE": {
        "Known Good IP": "IP Reputation",
        "Successful MFA": "User History",
        "Expected Business Hours Login": "Login Pattern",
    },
    "MALWARE_DETECTION": {
        "Signed Publisher": "File Reputation",
        "Approved Software": "File Reputation",
        "Clean History": "Endpoint History",
    },
    "UNAUTHORIZED_USB": {
        "Authorized Device": "Device Policy",
        "Approved Maintenance Window": "User History",
    },
    "SUSPICIOUS_PROCESS": {
        "Signed Admin Script": "Process Reputation",
        "Approved Change Window": "Command Analysis",
    },
    "NETWORK_ANOMALY": {
        "Scheduled Backup": "Network History",
        "Expected Traffic Pattern": "Network History",
    },
    "IMPOSSIBLE_TRAVEL": {
        "Known VPN Exit Node": "Geolocation Check",
        "Successful MFA": "Login History",
    },
}


class InvestigationEngine:
    def __init__(self):
        self.bfs = BFSInvestigator()

    def generate_simulated_evidence(self, alert, random_source):
        profiles = EVIDENCE_PROFILES.get(alert.alert_type)
        if not profiles:
            raise ValueError(f"No evidence profiles exist for {alert.alert_type}")
        signal_strength = (
            0.45 * alert.severity
            + 0.35 * alert.confidence
            + 0.20 * alert.frequency
        ) / 10
        malicious_chance = 0.15 + 0.55 * signal_strength
        roll = random_source.random()
        profile_name = (
            "malicious"
            if roll < malicious_chance
            else "suspicious"
            if roll < malicious_chance + 0.20
            else "benign"
        )
        return list(profiles[profile_name])

    def investigate(self, alert):
        graph = INVESTIGATION_GRAPHS.get(alert.alert_type)
        if not graph:
            return {"error": f"No investigation graph exists for {alert.alert_type}"}

        observations = (
            alert.simulated_evidence
            or OBSERVED_EVIDENCE.get(alert.alert_type, [])
        )
        graph = {
            node: list(neighbors)
            for node, neighbors in graph.items()
        }
        known_nodes = set(graph)
        known_nodes.update(
            neighbor
            for neighbors in graph.values()
            for neighbor in neighbors
        )
        for node in observations:
            if node not in known_nodes:
                parent = EVIDENCE_PARENTS.get(alert.alert_type, {}).get(node, "Alert")
                if parent not in graph:
                    parent = "Alert"
                graph.setdefault(parent, []).append(node)
                graph[node] = []

        evidence_paths = []
        for node in observations:
            # Search to evidence nodes, not a terminal named "Threat Confirmed".
            # The evidence result comes from the scenario's simulated telemetry.
            bfs = self.bfs.search(graph, start="Alert", goal=node)
            if bfs["found"]:
                evidence_paths.append({"node": node, "bfs": bfs})

        if not evidence_paths:
            return {"error": f"No simulated evidence is configured for {alert.alert_type}"}

        return {
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "graph": graph,
            "observed_evidence": observations,
            "evidence_paths": evidence_paths,
            "bfs": evidence_paths[0]["bfs"],
        }
