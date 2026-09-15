import json
from pathlib import Path

from models.alert import Alert


class AlertEngine:

    def __init__(self):
        self.alerts = []

    def load_scenarios(self):

        data_path = (
            Path(__file__).resolve().parent.parent
            / "data"
            / "scenarios.json"
        )

        with open(
            data_path,
            "r",
            encoding="utf-8"
        ) as file:

            scenarios = json.load(file)

        self.alerts = [
            Alert(**scenario)
            for scenario in scenarios
        ]

        return self.alerts

    def get_all_alerts(self):

        return self.alerts

    def get_alert(self, alert_id):

        for alert in self.alerts:

            if alert.id == alert_id:
                return alert

        return None

    def update_status(
        self,
        alert_id,
        status
    ):

        alert = self.get_alert(alert_id)

        if alert:
            alert.status = status

        return alert