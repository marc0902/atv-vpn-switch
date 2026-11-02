from atvvpn.network import detect_backend, detect_lan_if
from atvvpn.servers import parse_wg_conf

from conftest import KEY_C, KEY_D, conf_text

ATV = "192.168.178.123"
SWITCH_RULE = f"ip rule add priority 200 from {ATV} lookup 51820"


def _no_leftovers(runner):
    """Löschbefehle schlagen fehl = nichts mehr vorhanden."""
    runner.set(["ip", "rule", "del"], 1)
    runner.set(["iptables-nft", "-w", "-t"], 0)
    for table in ("nat", "filter", "mangle"):
        runner.set(["iptables-nft", "-w", "-t", table, "-D"], 1)


# --- Backend-Erkennung -------------------------------------------------------

def test_backend_prefers_docker_user_chain(runner):
    runner.set(["iptables-nft-save"], 0, "*filter\n:INPUT ACCEPT\n-A INPUT -j ACCEPT\n-A INPUT -j ACCEPT\n")
    runner.set(["iptables-legacy-save"], 0, "*filter\n:DOCKER-USER - [0:0]\n-A DOCKER-USER -j RETURN\n")
    assert detect_backend(runner) == "iptables-legacy"


def test_backend_nft_with_docker_user(runner):
    runner.set(["iptables-nft-save"], 0, "*filter\n:DOCKER-USER - [0:0]\n-A DOCKER-USER -j RETURN\n")
    runner.set(["iptables-legacy-save"], 0, "")
    assert detect_backend(runner) == "iptables-nft"


def test_backend_falls_back_to_rule_count(runner):
    runner.set(["iptables-nft-save"], 0, "-A X\n")
    runner.set(["iptables-legacy-save"], 0, "-A X\n-A Y\n-A Z\n")
    assert detect_backend(runner) == "iptables-legacy"


def test_backend_default_nft_when_errors(runner):
    runner.set(["iptables-nft-save"], 1)
    runner.set(["iptables-legacy-save"], 127)
    assert detect_backend(runner) == "iptables-nft"


def test_detect_lan_if(runner):
    runner.set(["ip", "-4", "route", "show", "default"], 0, "default via 192.168.178.1 dev eth0 proto static\n")
    assert detect_lan_if(runner) == "eth0"


# --- Grundeinrichtung --------------------------------------------------------

def test_setup_base_rules_and_nat(net, runner):
    runner.set(["iptables-nft", "-w", "-n", "-L", "DOCKER-USER"], 0)
    net.setup_base()
    cmds = runner.joined()
    assert f"ip rule add priority 100 from {ATV} to 192.168.178.0/24 lookup main" in cmds
    assert f"ip rule add priority 101 from {ATV} to 172.16.0.0/12 lookup main" in cmds
    assert "ip route replace blackhole default metric 1000 table 51820" in cmds
    assert "iptables-nft -w -t nat -A ATVVPN-POST -o wg-atv -j MASQUERADE" in cmds
    assert f"iptables-nft -w -t nat -A ATVVPN-POST -s {ATV} -o eth0 -j MASQUERADE" in cmds
    assert "iptables-nft -w -I DOCKER-USER 1 -j ATVVPN-FWD" in cmds
    assert f"iptables-nft -w -A ATVVPN-FWD -s {ATV} -j ACCEPT" in cmds
    assert f"iptables-nft -w -A ATVVPN-FWD -d {ATV} -j ACCEPT" in cmds
    # Schalter-Regel wird beim Start NICHT gesetzt (Standard Deutschland)
    assert SWITCH_RULE not in cmds


def test_setup_base_without_docker_uses_forward(net, runner):
    runner.set(["iptables-nft", "-w", "-n", "-L", "DOCKER-USER"], 1)
    net.setup_base()
    assert "iptables-nft -w -I FORWARD 1 -j ATVVPN-FWD" in runner.joined()


def test_setup_without_killswitch(net, runner, settings):
    settings.killswitch = False
    net.setup_base()
    assert not any("blackhole" in c for c in runner.joined())


def test_legacy_backend_used_consistently(settings, runner):
    from atvvpn.network import NetManager

    nm = NetManager(settings, runner, "iptables-legacy", "eth0")
    nm.setup_base()
    ipt = [c for c in runner.calls if c[0].startswith("iptables")]
    assert ipt and all(c[0] == "iptables-legacy" for c in ipt)


# --- Ein-/Ausschalten --------------------------------------------------------

def test_enable_sets_switch_rule_once(net, runner):
    runner.set(["ip", "rule", "del"], 1)
    net.enable_tunnel()
    cmds = runner.joined()
    assert cmds.count(SWITCH_RULE) == 1
    assert "ip route flush cache" in cmds
    assert f"conntrack -D -s {ATV}" in cmds
    # vorher Duplikate entfernen
    assert cmds.index(f"ip rule del priority 200 from {ATV} lookup 51820") < cmds.index(SWITCH_RULE)


def test_enable_removes_duplicates(net, runner):
    runner.fail_after[("ip", "rule", "del")] = 2  # zwei alte Regeln vorhanden
    net.enable_tunnel()
    dels = [c for c in runner.joined() if c.startswith("ip rule del priority 200")]
    assert len(dels) == 3  # 2 erfolgreich + 1 fehlgeschlagen
    assert runner.joined().count(SWITCH_RULE) == 1


def test_disable_removes_switch_rule(net, runner):
    runner.set(["ip", "rule", "del"], 1)
    net.disable_tunnel()
    cmds = runner.joined()
    assert f"ip rule del priority 200 from {ATV} lookup 51820" in cmds
    assert not any(c.startswith("ip rule add") for c in cmds)
    assert f"conntrack -D -s {ATV}" in cmds
    assert "ip route flush cache" in cmds


def test_conntrack_errors_ignored(net, runner):
    runner.set(["ip", "rule", "del"], 1)
    runner.set(["conntrack"], 1, "", "0 flow entries")
    net.disable_tunnel()  # darf nicht werfen


# --- Aufräumen ---------------------------------------------------------------

def test_cleanup_removes_everything(net, runner):
    _no_leftovers(runner)
    net.cleanup()
    cmds = runner.joined()
    assert f"ip rule del priority 100 from {ATV} to 192.168.178.0/24 lookup main" in cmds
    assert f"ip rule del priority 101 from {ATV} to 172.16.0.0/12 lookup main" in cmds
    assert f"ip rule del priority 200 from {ATV} lookup 51820" in cmds
    assert "ip route flush table 51820" in cmds
    assert "ip link del dev wg-atv" in cmds
    for jump in (
        "-t nat -D POSTROUTING -j ATVVPN-POST",
        "-t filter -D DOCKER-USER -j ATVVPN-FWD",
        "-t filter -D FORWARD -j ATVVPN-FWD",
        "-t filter -D OUTPUT -j ATVVPN-OUT",
        "-t mangle -D FORWARD -j ATVVPN-MSS",
    ):
        assert f"iptables-nft -w {jump}" in cmds
    for chain_cmd in ("-t nat -F ATVVPN-POST", "-t nat -X ATVVPN-POST", "-t filter -X ATVVPN-FWD"):
        assert f"iptables-nft -w {chain_cmd}" in cmds
    assert net.applied is None


def test_cleanup_removes_duplicate_jumps(net, runner):
    _no_leftovers(runner)
    runner.fail_after[("iptables-nft", "-w", "-t", "nat", "-D")] = 3
    net.cleanup()
    n = sum(1 for c in runner.joined() if c == "iptables-nft -w -t nat -D POSTROUTING -j ATVVPN-POST")
    assert n == 4


# --- Serverwechsel -----------------------------------------------------------

def test_apply_server_creates_interface(net, runner):
    cfg = parse_wg_conf(conf_text())
    runner.set(["ip", "link", "show"], 1)  # Schnittstelle existiert noch nicht
    runner.set(["ip", "rule", "del"], 1)
    net.apply_server(cfg)
    cmds = runner.joined()
    assert "ip link add dev wg-atv type wireguard" in cmds
    assert "wg set wg-atv private-key /dev/stdin" in cmds
    assert (f"wg set wg-atv peer {cfg.public_key} endpoint 203.0.113.10:51820 "
            "allowed-ips 0.0.0.0/0 persistent-keepalive 25") in cmds
    assert "ip addr add 10.64.0.2/32 dev wg-atv" in cmds
    assert "ip route replace default dev wg-atv table 51820" in cmds
    assert f"conntrack -D -s {ATV}" in cmds
    # Private Key nur über stdin, nie als Argument
    assert not any(cfg.private_key in c for c in cmds)
    assert cfg.private_key + "\n" in runner.inputs
    assert net.applied == cfg


def test_switch_server_reconfigures_live(net, runner):
    old = parse_wg_conf(conf_text())
    new = parse_wg_conf(conf_text(priv=KEY_C, pub=KEY_D, addr="10.65.1.3/32", endpoint="203.0.113.20:51820"))
    runner.set(["ip", "link", "show"], 0)  # existiert
    runner.set(["wg", "show", "wg-atv", "peers"], 0, old.public_key + "\n")
    net.apply_server(new)
    cmds = runner.joined()
    assert "ip link add dev wg-atv type wireguard" not in cmds
    assert f"wg set wg-atv peer {old.public_key} remove" in cmds
    assert f"wg set wg-atv peer {new.public_key} endpoint 203.0.113.20:51820 allowed-ips 0.0.0.0/0 persistent-keepalive 25" in cmds
    assert "ip -4 addr flush dev wg-atv" in cmds
    assert "ip addr add 10.65.1.3/32 dev wg-atv" in cmds
    assert f"conntrack -D -s {ATV}" in cmds
    # Schalterregel wird beim Serverwechsel nicht angefasst
    assert not any(c.startswith("ip rule") for c in cmds)
    # Peer erst entfernen, dann neuen setzen
    assert cmds.index(f"wg set wg-atv peer {old.public_key} remove") < cmds.index("wg set wg-atv private-key /dev/stdin")


def test_latest_handshake(net, runner):
    runner.set(["wg", "show", "wg-atv", "latest-handshakes"], 0, f"{KEY_D}\t1700000000\n")
    assert net.latest_handshake() == 1700000000
    runner.set(["wg", "show", "wg-atv", "latest-handshakes"], 1)
    assert net.latest_handshake() == 0
