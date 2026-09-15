from dataclasses import dataclass, asdict
from typing import Dict


@dataclass
class Asset:
    asset_id: str
    hostname: str
    asset_type: str
    criticality: int
    status: str = "ONLINE"


class SecurityEnvironment:

    def __init__(self):
        self.assets: Dict[str, Asset] = {
            "ADMIN-PC-01": Asset(
                asset_id="ADMIN-PC-01",
                hostname="admin-pc-01",
                asset_type="Workstation",
                criticality=10,
            ),
            "EMPLOYEE-PC-04": Asset(
                asset_id="EMPLOYEE-PC-04",
                hostname="employee-pc-04",
                asset_type="Workstation",
                criticality=7,
            ),
            "FILE-SERVER-01": Asset(
                asset_id="FILE-SERVER-01",
                hostname="file-server-01",
                asset_type="File Server",
                criticality=8,
            ),
            "WEB-SERVER-01": Asset(
                asset_id="WEB-SERVER-01",
                hostname="web-server-01",
                asset_type="Web Server",
                criticality=9,
            ),
            "DB-SERVER-01": Asset(
                asset_id="DB-SERVER-01",
                hostname="db-server-01",
                asset_type="Database Server",
                criticality=10,
            ),
        }

        self.blocked_ips = set()
        self.disabled_users = set()

    def isolate_endpoint(self, asset_id: str):
        if asset_id in self.assets:
            self.assets[asset_id].status = "ISOLATED"

    def restore_endpoint(self, asset_id: str):
        if asset_id in self.assets:
            self.assets[asset_id].status = "ONLINE"

    def block_ip(self, ip_address: str):
        if ip_address:
            self.blocked_ips.add(ip_address)

    def disable_user(self, username: str):
        if username:
            self.disabled_users.add(username)

    def get_state(self):
        return {
            "assets": [
                asdict(asset)
                for asset in self.assets.values()
            ],
            "blocked_ips": list(self.blocked_ips),
            "disabled_users": list(self.disabled_users),
        }