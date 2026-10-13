from dataclasses import dataclass, asdict
from typing import Dict


@dataclass
class Asset:
    asset_id: str
    hostname: str
    asset_type: str
    criticality: int
    estimated_loss_usd: int
    status: str = "ONLINE"


class SecurityEnvironment:

    def __init__(self):
        self._initial_assets = {
            "ADMIN-PC-01": Asset(
                asset_id="ADMIN-PC-01",
                hostname="admin-pc-01",
                asset_type="Workstation",
                criticality=10,
                estimated_loss_usd=180000,
            ),
            "EMPLOYEE-PC-04": Asset(
                asset_id="EMPLOYEE-PC-04",
                hostname="employee-pc-04",
                asset_type="Workstation",
                criticality=7,
                estimated_loss_usd=75000,
            ),
            "FILE-SERVER-01": Asset(
                asset_id="FILE-SERVER-01",
                hostname="file-server-01",
                asset_type="File Server",
                criticality=8,
                estimated_loss_usd=650000,
            ),
            "WEB-SERVER-01": Asset(
                asset_id="WEB-SERVER-01",
                hostname="web-server-01",
                asset_type="Web Server",
                criticality=9,
                estimated_loss_usd=420000,
            ),
            "DB-SERVER-01": Asset(
                asset_id="DB-SERVER-01",
                hostname="db-server-01",
                asset_type="Database Server",
                criticality=10,
                estimated_loss_usd=1800000,
            ),
            "IDENTITY-SERVER-01": Asset(
                asset_id="IDENTITY-SERVER-01",
                hostname="identity-server-01",
                asset_type="Identity Server",
                criticality=10,
                estimated_loss_usd=1450000,
            ),
            "SECURITY-MONITOR-01": Asset(
                asset_id="SECURITY-MONITOR-01",
                hostname="security-monitor-01",
                asset_type="Security Monitoring",
                criticality=8,
                estimated_loss_usd=350000,
            ),
            "APP-SERVER-01": Asset(
                asset_id="APP-SERVER-01",
                hostname="app-server-01",
                asset_type="Application Server",
                criticality=8,
                estimated_loss_usd=900000,
            ),
            "NETWORK-GATEWAY-01": Asset(
                asset_id="NETWORK-GATEWAY-01",
                hostname="network-gateway-01",
                asset_type="Network Gateway",
                criticality=9,
                estimated_loss_usd=1250000,
            ),
            "FINANCE-PC-02": Asset(
                asset_id="FINANCE-PC-02",
                hostname="finance-pc-02",
                asset_type="Workstation",
                criticality=8,
                estimated_loss_usd=260000,
            ),
        }

        self.assets: Dict[str, Asset] = {
            asset_id: Asset(**asdict(asset))
            for asset_id, asset in self._initial_assets.items()
        }
        self.blocked_ips = set()
        self.disabled_users = set()

    @staticmethod
    def effective_criticality(asset: Asset) -> float:
        loss_score = min(10, asset.estimated_loss_usd / 200000)
        return round((asset.criticality + loss_score) / 2, 2)

    def reset(self):
        self.assets = {
            asset_id: Asset(**asdict(asset))
            for asset_id, asset in self._initial_assets.items()
        }
        self.blocked_ips.clear()
        self.disabled_users.clear()

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