"""Einstiegspunkt: python -m atvvpn"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from .config import SettingsError, load_settings
from .controller import Controller
from .network import NetManager, NetworkError, detect_backend, detect_lan_if, read_ip_forward
from .runner import CommandError, CommandRunner
from .servers import ServerStore
from .web import make_server

log = logging.getLogger("atvvpn")


def main() -> int:
    logging.basicConfig(
        level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    try:
        settings = load_settings(dict(os.environ))
    except SettingsError as e:
        for line in str(e).splitlines():
            log.error("Konfigurationsfehler: %s", line)
        log.error("Bitte die Umgebungsvariablen im Portainer-Stack prüfen. Container wird beendet.")
        return 2

    if not read_ip_forward():
        log.error("net.ipv4.ip_forward ist auf dem Host ausgeschaltet. Bitte auf dem Pi "
                  "'sysctl -w net.ipv4.ip_forward=1' ausführen (dauerhaft in /etc/sysctl.conf). Abbruch.")
        return 3

    runner = CommandRunner()
    try:
        lan_if = settings.lan_if or detect_lan_if(runner)
    except NetworkError as e:
        log.error("%s", e)
        return 4
    backend = detect_backend(runner)
    net = NetManager(settings, runner, backend, lan_if)
    store = ServerStore(settings.config_dir, settings.wg_env)
    ctrl = Controller(settings, net, store)

    try:
        ctrl.start()
    except (CommandError, NetworkError, OSError) as e:
        log.error("Einrichtung fehlgeschlagen: %s", e)
        net.cleanup()
        return 5

    stop = threading.Event()

    def _signal(signum, _frame):
        log.info("Signal %s empfangen, räume auf …", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, _signal)
    signal.signal(signal.SIGINT, _signal)

    try:
        httpd = make_server(ctrl, settings.web_port)
    except OSError as e:
        log.error("Port %s kann nicht geöffnet werden: %s", settings.web_port, e)
        ctrl.shutdown()
        return 6
    threading.Thread(target=httpd.serve_forever, name="web", daemon=True).start()
    ctrl.start_threads()
    log.info("Weboberfläche auf Port %s%s. Modus: Deutschland", settings.web_port,
             " (Passwortschutz aktiv)" if settings.web_password else "")

    stop.wait()
    httpd.shutdown()
    ctrl.shutdown()
    log.info("Aufgeräumt, beendet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
