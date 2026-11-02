"""Erzeugt und führt alle Netzwerk-Befehle aus (ip, wg, iptables, conntrack).

Alle Befehle laufen über einen CommandRunner, damit sich die Logik in Tests
mit einem Mock prüfen lässt.
"""

from __future__ import annotations

import logging
import re

from .config import Settings
from .runner import CommandRunner
from .servers import WGConfig

log = logging.getLogger(__name__)

DOCKER_NETS = "172.16.0.0/12"
PRIO_LAN = 100
PRIO_DOCKER = 101
PRIO_SWITCH = 200

# Eigene iptables-Chains: lassen sich beim Aufräumen komplett entfernen
CHAIN_NAT = "ATVVPN-POST"
CHAIN_FWD = "ATVVPN-FWD"
CHAIN_OUT = "ATVVPN-OUT"
CHAIN_MANGLE = "ATVVPN-MSS"

MAX_DELETE_LOOPS = 20


class NetworkError(RuntimeError):
    pass


def detect_backend(runner: CommandRunner) -> str:
    """Wählt 'iptables-nft' oder 'iptables-legacy' passend zum Host.

    Entscheidend ist, wo die Chain DOCKER-USER existiert; sonst gewinnt das
    Backend mit den meisten Regeln. Bei Gleichstand: nft.
    """
    stats = {}
    for backend in ("iptables-nft", "iptables-legacy"):
        res = runner.run([f"{backend}-save"], check=False)
        out = res.stdout if res.ok else ""
        stats[backend] = (
            ":DOCKER-USER" in out,
            sum(1 for line in out.splitlines() if line.startswith("-A ")),
        )
    with_docker = [b for b, (has, _) in stats.items() if has]
    if len(with_docker) == 1:
        choice = with_docker[0]
    elif stats["iptables-legacy"][1] > stats["iptables-nft"][1]:
        choice = "iptables-legacy"
    else:
        choice = "iptables-nft"
    log.info(
        "iptables-Backend: %s (nft: DOCKER-USER=%s, %d Regeln; legacy: DOCKER-USER=%s, %d Regeln)",
        choice, *stats["iptables-nft"], *stats["iptables-legacy"],
    )
    return choice


def detect_lan_if(runner: CommandRunner) -> str:
    res = runner.run(["ip", "-4", "route", "show", "default"], check=False)
    m = re.search(r"\bdev\s+(\S+)", res.stdout)
    if not m:
        raise NetworkError("LAN-Schnittstelle konnte nicht über die Default-Route ermittelt werden. Bitte LAN_IF setzen.")
    return m.group(1)


def read_ip_forward(path: str = "/proc/sys/net/ipv4/ip_forward") -> bool:
    try:
        with open(path) as fh:
            return fh.read().strip() == "1"
    except OSError:
        return False


class NetManager:
    def __init__(self, settings: Settings, runner: CommandRunner, backend: str, lan_if: str):
        self.s = settings
        self.r = runner
        self.ipt = backend
        self.lan_if = lan_if
        self.wg_if = settings.wg_if
        self.table = str(settings.wg_table)
        self.applied: WGConfig | None = None

    # --- Hilfen ----------------------------------------------------------

    def _ipt(self, *args: str, check: bool = True):
        return self.r.run([self.ipt, "-w", *args], check=check)

    def _delete_repeatedly(self, cmd: list[str]) -> None:
        """Löscht einen Eintrag so oft, bis er nicht mehr existiert (auch Duplikate)."""
        for _ in range(MAX_DELETE_LOOPS):
            if not self.r.run(cmd, check=False).ok:
                break

    def _rule_specs(self) -> list[tuple[int, list[str]]]:
        atv = self.s.atv_ip
        return [
            (PRIO_LAN, ["from", atv, "to", self.s.lan_cidr, "lookup", "main"]),
            (PRIO_DOCKER, ["from", atv, "to", DOCKER_NETS, "lookup", "main"]),
        ]

    def _switch_rule(self) -> list[str]:
        return ["from", self.s.atv_ip, "lookup", self.table]

    def has_docker_user(self) -> bool:
        return self._ipt("-n", "-L", "DOCKER-USER", check=False).ok

    def _try_sysctl(self, key: str, value: str) -> None:
        path = "/proc/sys/" + key.replace(".", "/")
        try:
            with open(path, "w") as fh:
                fh.write(value)
        except OSError:
            log.debug("sysctl %s=%s nicht möglich (nur lesbar)", key, value)

    # --- Aufräumen -------------------------------------------------------

    def cleanup(self) -> None:
        """Entfernt alle eigenen Regeln, Routen, iptables-Einträge und die WG-Schnittstelle."""
        for prio, spec in self._rule_specs():
            self._delete_repeatedly(["ip", "rule", "del", "priority", str(prio), *spec])
        self._delete_repeatedly(["ip", "rule", "del", "priority", str(PRIO_SWITCH), *self._switch_rule()])
        self.r.run(["ip", "route", "flush", "table", self.table], check=False)
        self.r.run(["ip", "link", "del", "dev", self.wg_if], check=False)
        self.applied = None

        jumps = [
            ("nat", "POSTROUTING", CHAIN_NAT),
            ("filter", "DOCKER-USER", CHAIN_FWD),
            ("filter", "FORWARD", CHAIN_FWD),
            ("filter", "OUTPUT", CHAIN_OUT),
            ("mangle", "FORWARD", CHAIN_MANGLE),
        ]
        for table, parent, chain in jumps:
            self._delete_repeatedly([self.ipt, "-w", "-t", table, "-D", parent, "-j", chain])
        for table, chain in (("nat", CHAIN_NAT), ("filter", CHAIN_FWD), ("filter", CHAIN_OUT), ("mangle", CHAIN_MANGLE)):
            self._ipt("-t", table, "-F", chain, check=False)
            self._ipt("-t", table, "-X", chain, check=False)
        self.r.run(["ip", "route", "flush", "cache"], check=False)

    # --- Grundeinrichtung (Modus Deutschland) ----------------------------

    def setup_base(self) -> None:
        """Richtet alles ein, was in beiden Modi gilt. Danach ist 'Deutschland' aktiv."""
        atv = self.s.atv_ip

        # Keine ICMP-Redirects an das Apple TV: sonst würde es die Fritzbox direkt nutzen
        self._try_sysctl("net.ipv4.conf.all.send_redirects", "0")
        self._try_sysctl(f"net.ipv4.conf.{self.lan_if}.send_redirects", "0")

        for prio, spec in self._rule_specs():
            self.r.run(["ip", "rule", "add", "priority", str(prio), *spec])

        # Tunnel-Tabelle: Kill-Switch als Blackhole mit hoher Metrik
        if self.s.killswitch:
            self.r.run(["ip", "route", "replace", "blackhole", "default", "metric", "1000", "table", self.table])

        # NAT
        self._ipt("-t", "nat", "-N", CHAIN_NAT)
        self._ipt("-t", "nat", "-A", CHAIN_NAT, "-o", self.wg_if, "-j", "MASQUERADE")
        self._ipt("-t", "nat", "-A", CHAIN_NAT, "-s", atv, "-o", self.lan_if, "-j", "MASQUERADE")
        self._ipt("-t", "nat", "-I", "POSTROUTING", "1", "-j", CHAIN_NAT)

        # Forwarding erlauben (Docker setzt FORWARD auf DROP)
        self._ipt("-N", CHAIN_FWD)
        self._ipt("-A", CHAIN_FWD, "-s", atv, "-j", "ACCEPT")
        self._ipt("-A", CHAIN_FWD, "-d", atv, "-j", "ACCEPT")
        parent = "DOCKER-USER" if self.has_docker_user() else "FORWARD"
        self._ipt("-I", parent, "1", "-j", CHAIN_FWD)

        # Ausgehende ICMP-Redirects an das Apple TV verwerfen (falls sysctl nur lesbar)
        self._ipt("-N", CHAIN_OUT)
        self._ipt("-A", CHAIN_OUT, "-d", atv, "-p", "icmp", "--icmp-type", "redirect", "-j", "DROP")
        self._ipt("-I", "OUTPUT", "1", "-j", CHAIN_OUT)

        # MSS an die Tunnel-MTU anpassen
        self._ipt("-t", "mangle", "-N", CHAIN_MANGLE)
        self._ipt("-t", "mangle", "-A", CHAIN_MANGLE, "-o", self.wg_if, "-p", "tcp",
                  "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
        self._ipt("-t", "mangle", "-I", "FORWARD", "1", "-j", CHAIN_MANGLE)

        self.r.run(["ip", "route", "flush", "cache"], check=False)
        log.info("Grundeinrichtung fertig (LAN_IF=%s, Tabelle %s, Kill-Switch %s)",
                 self.lan_if, self.table, "an" if self.s.killswitch else "aus")

    # --- WireGuard -------------------------------------------------------

    def link_exists(self) -> bool:
        return self.r.run(["ip", "link", "show", "dev", self.wg_if], check=False).ok

    def apply_server(self, cfg: WGConfig) -> None:
        """Baut die WG-Schnittstelle auf bzw. konfiguriert sie im Betrieb um."""
        wg = self.wg_if
        if not self.link_exists():
            res = self.r.run(["ip", "link", "add", "dev", wg, "type", "wireguard"], check=False)
            if not res.ok:
                raise NetworkError(
                    f"WireGuard-Schnittstelle konnte nicht angelegt werden: {res.stderr.strip()}"
                )
            self.applied = None
        else:
            # Alte Peers entfernen (Kill-Switch hält den Verkehr währenddessen zurück)
            res = self.r.run(["wg", "show", wg, "peers"], check=False)
            for peer in res.stdout.split():
                self.r.run(["wg", "set", wg, "peer", peer, "remove"], check=False)

        # Private Key über stdin, nie als Argument oder Datei
        self.r.run(["wg", "set", wg, "private-key", "/dev/stdin"], input=cfg.private_key + "\n")
        self.r.run([
            "wg", "set", wg, "peer", cfg.public_key, "endpoint", cfg.endpoint,
            "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25",
        ])
        self.r.run(["ip", "-4", "addr", "flush", "dev", wg], check=False)
        self.r.run(["ip", "addr", "add", cfg.address, "dev", wg])
        self.r.run(["ip", "link", "set", "dev", wg, "up"])
        self.r.run(["ip", "route", "replace", "default", "dev", wg, "table", self.table])
        self.applied = cfg
        self.reset_connections()

    def latest_handshake(self) -> int:
        """Unix-Zeit des letzten Handshakes, 0 = noch keiner / keine Schnittstelle."""
        res = self.r.run(["wg", "show", self.wg_if, "latest-handshakes"], check=False)
        best = 0
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                best = max(best, int(parts[1]))
        return best

    # --- Schalter --------------------------------------------------------

    def reset_connections(self) -> None:
        self.r.run(["ip", "route", "flush", "cache"], check=False)
        self.r.run(["conntrack", "-D", "-s", self.s.atv_ip], check=False)

    def enable_tunnel(self) -> None:
        """Modus Albanien: Regel 200 setzen (vorher Duplikate entfernen)."""
        self._delete_repeatedly(["ip", "rule", "del", "priority", str(PRIO_SWITCH), *self._switch_rule()])
        self.r.run(["ip", "rule", "add", "priority", str(PRIO_SWITCH), *self._switch_rule()])
        self.reset_connections()

    def disable_tunnel(self) -> None:
        """Modus Deutschland: Regel 200 entfernen."""
        self._delete_repeatedly(["ip", "rule", "del", "priority", str(PRIO_SWITCH), *self._switch_rule()])
        self.reset_connections()

    def warn_rp_filter(self) -> None:
        try:
            with open("/proc/sys/net/ipv4/conf/all/rp_filter") as fh:
                if fh.read().strip() == "1":
                    log.warning(
                        "rp_filter ist strikt (1). Falls im Modus Albanien keine Antworten ankommen: "
                        "auf dem Pi 'sysctl -w net.ipv4.conf.all.rp_filter=2' setzen."
                    )
        except OSError:
            pass
        self._try_sysctl(f"net.ipv4.conf.{self.wg_if}.rp_filter", "0")
