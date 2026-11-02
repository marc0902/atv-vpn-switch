from datetime import datetime, timezone

import pytest

from atvvpn.config import SettingsError, load_settings
from atvvpn.controller import MODE_AL, MODE_DE, Controller, UserError
from atvvpn.servers import ServerStore

from conftest import KEY_C, KEY_D, conf_text

ATV = "192.168.178.123"


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def store(settings):
    s = ServerStore(settings.config_dir)
    s.ensure_dirs()
    return s


@pytest.fixture
def ctrl(settings, net, runner, store):
    runner.set(["ip", "rule", "del"], 1)
    runner.set(["ip", "link", "show"], 1)
    for table in ("nat", "filter", "mangle"):
        runner.set(["iptables-nft", "-w", "-t", table, "-D"], 1)
    return Controller(settings, net, store, clock=Clock())


def test_start_without_server_is_germany(ctrl, runner):
    ctrl.start()
    assert ctrl.mode == MODE_DE
    assert ctrl.active is None
    with pytest.raises(UserError):
        ctrl.set_mode(MODE_AL)


def test_start_uses_saved_server_and_germany(ctrl, store, runner):
    store.save("al-tia-wg-001.conf", conf_text())
    store.save("al-tia-wg-002.conf", conf_text(priv=KEY_C, pub=KEY_D))
    store.save_active("al-tia-wg-002.conf")
    ctrl.start()
    assert ctrl.active == "al-tia-wg-002.conf"
    assert ctrl.mode == MODE_DE
    assert not any(c.startswith("ip rule add priority 200") for c in runner.joined())


def test_toggle(ctrl, store, runner):
    store.save("a.conf", conf_text())
    ctrl.start()
    runner.clear()
    ctrl.toggle()
    assert ctrl.mode == MODE_AL
    assert f"ip rule add priority 200 from {ATV} lookup 51820" in runner.joined()
    ctrl.toggle()
    assert ctrl.mode == MODE_DE


def test_select_keeps_mode_and_persists(ctrl, store, runner):
    store.save("a.conf", conf_text())
    store.save("b.conf", conf_text(priv=KEY_C, pub=KEY_D))
    ctrl.start()
    ctrl.set_mode(MODE_AL)
    runner.set(["ip", "link", "show"], 0)
    runner.clear()
    ctrl.select_server("b.conf")
    assert ctrl.mode == MODE_AL
    assert ctrl.active == "b.conf"
    assert store.load_active() == "b.conf"
    assert not any("rule del priority 200" in c for c in runner.joined())
    assert f"conntrack -D -s {ATV}" in runner.joined()


def test_delete_active_refused(ctrl, store):
    store.save("a.conf", conf_text())
    store.save("b.conf", conf_text())
    ctrl.start()
    with pytest.raises(UserError):
        ctrl.delete_server("a.conf")
    ctrl.delete_server("b.conf")
    assert [e.name for e in store.list()] == ["a.conf"]


def test_refresh_activates_first_new_server(ctrl, store):
    ctrl.start()
    assert ctrl.active is None
    store.save("x.conf", conf_text())
    ctrl.refresh()
    assert ctrl.active == "x.conf"


def test_auto_reset(ctrl, store, runner):
    store.save("a.conf", conf_text())
    ctrl.start()
    ctrl.set_mode(MODE_AL)
    ctrl.reset_tick(datetime(2026, 11, 2, 20, 0, tzinfo=timezone.utc))
    assert ctrl.next_reset_utc == datetime(2026, 11, 3, 2, 0, tzinfo=timezone.utc)
    ctrl.reset_tick(datetime(2026, 11, 3, 1, 59, tzinfo=timezone.utc))
    assert ctrl.mode == MODE_AL
    ctrl.reset_tick(datetime(2026, 11, 3, 2, 0, 10, tzinfo=timezone.utc))
    assert ctrl.mode == MODE_DE
    assert ctrl.next_reset_utc == datetime(2026, 11, 4, 2, 0, tzinfo=timezone.utc)


def test_auto_reset_disabled(settings, net, store):
    settings.auto_reset_time = ""
    c = Controller(settings, net, store)
    c.reset_tick(datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert c.next_reset_utc is None


def test_failover_switches_after_timeout(ctrl, store, runner, settings):
    settings.auto_failover = True
    store.save("a.conf", conf_text())
    store.save("b.conf", conf_text(priv=KEY_C, pub=KEY_D))
    ctrl.start()
    ctrl.set_mode(MODE_AL)
    runner.set(["wg", "show", "wg-atv", "latest-handshakes"], 0, "x\t0\n")
    ctrl.clock.t += 100
    ctrl.failover_tick()
    assert ctrl.active == "a.conf"
    ctrl.clock.t += 100  # > 180 s ohne Handshake
    ctrl.failover_tick()
    assert ctrl.active == "b.conf"
    assert ctrl.mode == MODE_AL


def test_failover_off_by_default(ctrl, store, runner):
    store.save("a.conf", conf_text())
    store.save("b.conf", conf_text(priv=KEY_C, pub=KEY_D))
    ctrl.start()
    ctrl.set_mode(MODE_AL)
    ctrl.clock.t += 10_000
    ctrl.failover_tick()
    assert ctrl.active == "a.conf"


def test_status_tunnel_connected(ctrl, store, runner):
    store.save("a.conf", conf_text())
    ctrl.start()
    runner.set(["wg", "show", "wg-atv", "latest-handshakes"], 0, f"x\t{int(ctrl.clock.t) - 30}\n")
    st = ctrl.status()
    assert st["tunnel_connected"] is True
    assert st["active_server"] == "a.conf"
    runner.set(["wg", "show", "wg-atv", "latest-handshakes"], 0, f"x\t{int(ctrl.clock.t) - 500}\n")
    assert ctrl.status()["tunnel_connected"] is False


def test_shutdown_cleans_up(ctrl, store, runner):
    store.save("a.conf", conf_text())
    ctrl.start()
    ctrl.set_mode(MODE_AL)
    runner.clear()
    ctrl.shutdown()
    cmds = runner.joined()
    assert "ip link del dev wg-atv" in cmds
    assert f"ip rule del priority 200 from {ATV} lookup 51820" in cmds


# --- Einstellungen -----------------------------------------------------------

def test_settings_required():
    with pytest.raises(SettingsError) as exc:
        load_settings({})
    assert "ATV_IP" in str(exc.value)


def test_settings_defaults():
    s = load_settings({"ATV_IP": ATV})
    assert s.lan_cidr == "192.168.178.0/24"
    assert s.wg_table == 51820 and s.web_port == 8099
    assert s.killswitch is True and s.auto_failover is False
    assert s.auto_reset_time == "03:00" and s.tz == "Europe/Berlin"


def test_settings_reset_empty_and_bools():
    s = load_settings({"ATV_IP": ATV, "AUTO_RESET_TIME": "", "KILLSWITCH": "false", "AUTO_FAILOVER": "true"})
    assert s.auto_reset_time == "" and s.killswitch is False and s.auto_failover is True


def test_settings_invalid():
    with pytest.raises(SettingsError):
        load_settings({"ATV_IP": "192.168.178.xxx"})
    with pytest.raises(SettingsError):
        load_settings({"ATV_IP": ATV, "LAN_CIDR": "kaputt"})
