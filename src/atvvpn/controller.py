"""Zustand (Modus, aktiver Server) und Hintergrund-Threads."""

from __future__ import annotations

import logging
import threading
import time as _time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from .config import Settings, parse_reset_time
from .network import NetManager, NetworkError
from .schedule import next_reset
from .servers import ENV_SERVER_NAME, ConfError, ServerStore

log = logging.getLogger(__name__)

MODE_DE = "de"
MODE_AL = "al"
HANDSHAKE_TIMEOUT = 180  # Sekunden
FAILOVER_CHECK = 30


class UserError(Exception):
    """Fehler, der in der Weboberfläche angezeigt wird."""


class Controller:
    def __init__(self, settings: Settings, net: NetManager, store: ServerStore, clock=_time.time):
        self.s = settings
        self.net = net
        self.store = store
        self.clock = clock
        self.lock = threading.RLock()
        self.mode = MODE_DE
        self.active: str | None = None
        self.tunnel_since = 0.0  # Zeitpunkt von Serverwechsel/Einschalten (für Failover)
        self.tz = ZoneInfo(settings.tz)
        self.reset_at = parse_reset_time(settings.auto_reset_time)
        self.next_reset_utc: datetime | None = None
        self.stop_event = threading.Event()

    # --- Start -----------------------------------------------------------

    def start(self) -> None:
        """Grundeinrichtung, aktiven Server laden. Modus ist danach immer Deutschland."""
        self.store.ensure_dirs()
        self.net.cleanup()
        self.net.setup_base()
        with self.lock:
            entries = [e for e in self.store.list() if e.valid]
            saved = self.store.load_active()
            chosen = next((e for e in entries if e.name == saved), None) or (entries[0] if entries else None)
            if chosen is None:
                log.warning("Kein VPN-Server vorhanden. Modus Deutschland funktioniert; "
                            "bitte in der Weboberfläche einen Server hinzufügen.")
                return
            try:
                self._apply(chosen.name)
            except NetworkError as e:
                log.error("Server %s konnte nicht aktiviert werden: %s", chosen.name, e)

    def _apply(self, name: str) -> None:
        entry = self.store.get(name)
        if entry is None or not entry.valid:
            raise UserError(f"Server '{name}' ist nicht vorhanden oder fehlerhaft.")
        self.net.apply_server(entry.config)
        self.net.warn_rp_filter()
        self.active = name
        self.tunnel_since = self.clock()
        if name != ENV_SERVER_NAME:
            self.store.save_active(name)
        log.info("Aktiver Server: %s (%s)", name, entry.config.endpoint)

    # --- Modus -----------------------------------------------------------

    def set_mode(self, mode: str, reason: str = "Weboberfläche") -> None:
        with self.lock:
            if mode == MODE_AL:
                if self.net.applied is None:
                    raise UserError("Kein VPN-Server aktiv. Bitte zuerst unten einen Server hinzufügen.")
                self.net.enable_tunnel()
                self.tunnel_since = self.clock()
            else:
                self.net.disable_tunnel()
            changed = self.mode != mode
            self.mode = mode
            if changed:
                log.info("Modus: %s (%s)", "Albanien" if mode == MODE_AL else "Deutschland", reason)

    def toggle(self) -> None:
        with self.lock:
            self.set_mode(MODE_DE if self.mode == MODE_AL else MODE_AL)

    # --- Server ----------------------------------------------------------

    def select_server(self, name: str, reason: str = "Weboberfläche") -> None:
        """Wechsel im laufenden Betrieb; der Modus bleibt erhalten."""
        with self.lock:
            try:
                self._apply(name)
            except NetworkError as e:
                raise UserError(str(e))
            log.info("Serverwechsel auf %s (%s), Modus bleibt %s", name, reason,
                     "Albanien" if self.mode == MODE_AL else "Deutschland")

    def refresh(self) -> None:
        """Verzeichnis neu lesen; geänderte aktive Datei neu anwenden, ersten Server übernehmen."""
        with self.lock:
            entries = self.store.list()
            if self.active == ENV_SERVER_NAME and not any(e.name == ENV_SERVER_NAME for e in entries):
                self.active = None  # Fallback abgelöst, sobald echte Dateien vorhanden sind
            if self.active:
                entry = next((e for e in entries if e.name == self.active), None)
                if entry and entry.valid and entry.config != self.net.applied:
                    log.info("Datei %s wurde geändert, wende neu an", self.active)
                    try:
                        self._apply(self.active)
                    except (NetworkError, UserError) as e:
                        log.error("Neu anwenden fehlgeschlagen: %s", e)
            else:
                first = next((e for e in entries if e.valid), None)
                if first:
                    try:
                        self._apply(first.name)
                    except (NetworkError, UserError) as e:
                        log.error("Server %s konnte nicht aktiviert werden: %s", first.name, e)

    def delete_server(self, name: str) -> None:
        with self.lock:
            if name == self.active:
                raise UserError("Der aktive Server kann nicht gelöscht werden.")
            if name == ENV_SERVER_NAME:
                raise UserError("Dieser Eintrag kommt aus den Umgebungsvariablen.")
            try:
                self.store.delete(name)
            except ConfError as e:
                raise UserError(str(e))
            log.info("Server %s gelöscht", name)

    def after_write(self, names: list[str]) -> None:
        """Nach Upload/Einfügen: ggf. aktiven Server neu anwenden oder ersten aktivieren."""
        self.refresh()

    # --- Status ----------------------------------------------------------

    def handshake_age(self) -> int | None:
        hs = self.net.latest_handshake() if self.net.applied else 0
        if not hs:
            return None
        return max(0, int(self.clock() - hs))

    def status(self) -> dict:
        with self.lock:
            age = self.handshake_age()
            entry = self.store.get(self.active) if self.active else None
            return {
                "mode": self.mode,
                "mode_label": "🇦🇱 Albanien (Mullvad)" if self.mode == MODE_AL else "🇩🇪 Deutschland (normal)",
                "tunnel_connected": age is not None and age < HANDSHAKE_TIMEOUT,
                "handshake_age_seconds": age,
                "active_server": self.active,
                "active_endpoint": entry.config.endpoint if entry and entry.valid else
                (self.net.applied.endpoint if self.net.applied else None),
                "active_missing": bool(self.active) and entry is None,
                "killswitch": self.s.killswitch,
                "auto_failover": self.s.auto_failover,
                "auto_reset_time": self.s.auto_reset_time or None,
                "next_reset": self.next_reset_utc.astimezone(self.tz).isoformat() if self.next_reset_utc else None,
                "atv_ip": self.s.atv_ip,
            }

    # --- Hintergrund -----------------------------------------------------

    def reset_tick(self, now: datetime) -> None:
        """Wird regelmäßig aufgerufen; setzt zur geplanten Zeit auf Deutschland zurück."""
        if self.reset_at is None:
            return
        if self.next_reset_utc is None:
            self.next_reset_utc = next_reset(now, *self.reset_at, self.tz)
            return
        if now >= self.next_reset_utc:
            with self.lock:
                if self.mode == MODE_AL:
                    self.set_mode(MODE_DE, reason="automatisches Zurücksetzen")
                    log.info("Automatisches Zurücksetzen um %s: Modus Deutschland aktiv", self.s.auto_reset_time)
                else:
                    log.info("Automatisches Zurücksetzen um %s: war bereits Deutschland", self.s.auto_reset_time)
            self.next_reset_utc = next_reset(now, *self.reset_at, self.tz)
            log.info("Nächstes Zurücksetzen: %s", self.next_reset_utc.astimezone(self.tz).strftime("%d.%m.%Y %H:%M %Z"))

    def failover_tick(self) -> None:
        if not self.s.auto_failover:
            return
        with self.lock:
            if self.mode != MODE_AL or not self.active:
                return
            now = self.clock()
            hs = self.net.latest_handshake()
            last_ok = max(hs, self.tunnel_since)
            if now - last_ok <= HANDSHAKE_TIMEOUT:
                return
            names = [e.name for e in self.store.list() if e.valid]
            if len(names) < 2:
                return
            idx = names.index(self.active) if self.active in names else -1
            nxt = names[(idx + 1) % len(names)]
            log.warning("Kein Handshake seit über %d s bei %s – automatischer Wechsel auf %s",
                        HANDSHAKE_TIMEOUT, self.active, nxt)
            try:
                self.select_server(nxt, reason="automatischer Serverwechsel")
            except UserError as e:
                log.error("Automatischer Serverwechsel fehlgeschlagen: %s", e)
                self.tunnel_since = now

    def _reset_loop(self) -> None:
        if self.reset_at is None:
            log.info("Automatisches Zurücksetzen ist deaktiviert (AUTO_RESET_TIME leer)")
            return
        self.reset_tick(datetime.now(timezone.utc))
        log.info("Automatisches Zurücksetzen täglich um %s (%s), nächstes: %s", self.s.auto_reset_time,
                 self.s.tz, self.next_reset_utc.astimezone(self.tz).strftime("%d.%m.%Y %H:%M %Z"))
        while not self.stop_event.wait(20):
            try:
                self.reset_tick(datetime.now(timezone.utc))
            except Exception:
                log.exception("Fehler beim automatischen Zurücksetzen")

    def _failover_loop(self) -> None:
        while not self.stop_event.wait(FAILOVER_CHECK):
            try:
                self.failover_tick()
            except Exception:
                log.exception("Fehler beim automatischen Serverwechsel")

    def start_threads(self) -> None:
        threading.Thread(target=self._reset_loop, name="auto-reset", daemon=True).start()
        if self.s.auto_failover:
            log.info("Automatischer Serverwechsel ist aktiv")
            threading.Thread(target=self._failover_loop, name="failover", daemon=True).start()

    def shutdown(self) -> None:
        self.stop_event.set()
        with self.lock:
            self.net.cleanup()
            self.mode = MODE_DE
