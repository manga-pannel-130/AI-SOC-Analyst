class ThreatEngine:

    EVIDENCE_SCORES = {

        "Known Malicious IP": 30,
        "IP Geographic Anomaly": 15,
        "Previous Failed Logins": 20,
        "MFA Status": 10,
        "Login Frequency": 15,
        "Login Time Anomaly": 10,

        "Known Malicious Hash": 35,
        "Suspicious Parent Process": 25,
        "Previous Malware Alerts": 25,
        "Deep File Analysis": 20,

        "Unauthorized Device": 30,
        "Previous USB Events": 15,
        "Sensitive File Access": 30,

        "Known Malicious Process": 35,
        "Encoded Command": 25,
        "Deep Process Analysis": 20,

        "Abnormal Volume": 25,
        "Suspicious Destination": 30,
        "Previous Traffic Pattern": 15,
        "Deep Traffic Analysis": 20,

        "Impossible Distance": 30,
        "Recent Login": 20,
        "Unknown Device": 25,
        "Deep Identity Analysis": 20
    }

    def calculate_score(self, path):

        evidence = []

        score = 0

        for node in path:

            if node in self.EVIDENCE_SCORES:

                points = self.EVIDENCE_SCORES[node]

                score += points

                evidence.append({
                    "node": node,
                    "points": points
                })

        score = min(score, 100)

        if score >= 60:
            classification = "CONFIRMED"

        elif score >= 30:
            classification = "SUSPICIOUS"

        else:
            classification = "BENIGN"

        return {
            "score": score,
            "classification": classification,
            "evidence": evidence
        }