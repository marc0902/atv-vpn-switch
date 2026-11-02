import base64

import pytest

from atvvpn.config import Settings
from atvvpn.network import NetManager
from atvvpn.runner import Result

# Offensichtlich unechte Test-Schlüssel
KEY_A = base64.b64encode(b"\x01" * 32).decode()
KEY_B = base64.b64encode(b"\x02" * 32).decode()
KEY_C = base64.b64encode(b"\x03" * 32).decode()
KEY_D = base64.b64encode(b"\x04" * 32).decode()


def conf_text(priv=KEY_A, pub=KEY_B, addr="10.64.0.2/32,fc00:bbbb:bbbb:bb01::1/128", endpoint="203.0.113.10:51820"):
    return f"""[Interface]
# Device: Test
PrivateKey = {priv}
Address = {addr}
DNS = 10.64.0.1

[Peer]
PublicKey = {pub}
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = {endpoint}
"""


class MockRunner:
    """Zeichnet Befehle auf; Antworten per Präfix konfigurierbar."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.inputs: list[str | None] = []
        self.responses: dict[tuple, Result] = {}
        self.fail_after: dict[tuple, int] = {}  # Präfix -> Anzahl erfolgreicher Aufrufe

    def set(self, prefix, returncode=0, stdout="", stderr=""):
        self.responses[tuple(prefix)] = Result(returncode, stdout, stderr)

    def run(self, cmd, check=True, input=None):
        self.calls.append(list(cmd))
        self.inputs.append(input)
        for prefix, limit in self.fail_after.items():
            if tuple(cmd[: len(prefix)]) == prefix:
                count = sum(1 for c in self.calls if tuple(c[: len(prefix)]) == prefix)
                if count > limit:
                    return Result(1, "", "not found")
                return Result(0)
        best = None
        for prefix, res in self.responses.items():
            if tuple(cmd[: len(prefix)]) == prefix and (best is None or len(prefix) > len(best[0])):
                best = (prefix, res)
        return best[1] if best else Result(0)

    def joined(self):
        return [" ".join(c) for c in self.calls]

    def clear(self):
        self.calls.clear()
        self.inputs.clear()


@pytest.fixture
def settings(tmp_path):
    return Settings(atv_ip="192.168.178.123", lan_cidr="192.168.178.0/24", config_dir=str(tmp_path))


@pytest.fixture
def runner():
    return MockRunner()


@pytest.fixture
def net(settings, runner):
    return NetManager(settings, runner, "iptables-nft", "eth0")
