"""VPN-Server als wg-quick-Dateien im Volume: Parser, Dateinamen-Prüfung, Import."""

from __future__ import annotations

import base64
import binascii
import io
import ipaddress
import json
import logging
import os
import re
import zipfile
from dataclasses import dataclass

log = logging.getLogger(__name__)

FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.conf$")
MAX_CONF_SIZE = 64 * 1024
MAX_ZIP_MEMBERS = 200
ENV_SERVER_NAME = "(Umgebungsvariablen)"


class ConfError(ValueError):
    """Ungültige WireGuard-Konfiguration."""


@dataclass(frozen=True)
class WGConfig:
    private_key: str
    address: str  # IPv4 mit Präfix, z. B. 10.64.1.2/32
    public_key: str
    endpoint: str  # host:port

    @property
    def private_key_hint(self) -> str:
        return mask_key(self.private_key)


@dataclass
class ServerEntry:
    name: str
    config: WGConfig | None
    error: str = ""

    @property
    def valid(self) -> bool:
        return self.config is not None


def mask_key(key: str) -> str:
    return (key[:4] + "…") if key else ""


def _check_key(value: str, label: str) -> str:
    value = value.strip()
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) != 32:
        raise ConfError(f"{label} ist kein gültiger WireGuard-Schlüssel.")
    return value


def _check_endpoint(value: str) -> str:
    value = value.strip()
    m = re.fullmatch(r"(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):(\d{1,5})", value)
    if not m or not 0 < int(m.group(2)) < 65536:
        raise ConfError(f"Endpoint '{value}' ist ungültig (erwartet host:port).")
    return value


def _pick_ipv4(value: str) -> str:
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            iface = ipaddress.ip_interface(part)
        except ValueError:
            raise ConfError(f"Address '{part}' ist ungültig.")
        if iface.version == 4:
            return str(iface)  # ohne Präfix wird /32 ergänzt
    raise ConfError("Address enthält keine IPv4-Adresse.")


def parse_wg_conf(text: str) -> WGConfig:
    """Liest eine wg-quick-Datei. DNS, AllowedIPs und IPv6 werden ignoriert."""
    section = None
    iface: dict[str, str] = {}
    peer: dict[str, str] = {}
    peers_seen = 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section == "peer":
                peers_seen += 1
            elif section != "interface":
                raise ConfError(f"Zeile {lineno}: unbekannter Abschnitt [{line[1:-1]}].")
            continue
        if "=" not in line:
            raise ConfError(f"Zeile {lineno}: 'Schlüssel = Wert' erwartet.")
        key, value = (s.strip() for s in line.split("=", 1))
        key = key.lower()
        if section == "interface":
            iface.setdefault(key, value)
        elif section == "peer":
            if peers_seen == 1:  # nur den ersten Peer verwenden
                peer.setdefault(key, value)
        else:
            raise ConfError(f"Zeile {lineno}: Eintrag außerhalb eines Abschnitts.")

    if not iface:
        raise ConfError("Abschnitt [Interface] fehlt.")
    if not peer:
        raise ConfError("Abschnitt [Peer] fehlt.")
    for key, label, src in (
        ("privatekey", "PrivateKey", iface),
        ("address", "Address", iface),
        ("publickey", "PublicKey", peer),
        ("endpoint", "Endpoint", peer),
    ):
        if not src.get(key):
            raise ConfError(f"{label} fehlt.")

    return WGConfig(
        private_key=_check_key(iface["privatekey"], "PrivateKey"),
        address=_pick_ipv4(iface["address"]),
        public_key=_check_key(peer["publickey"], "PublicKey"),
        endpoint=_check_endpoint(peer["endpoint"]),
    )


def config_from_env(wg_env: dict) -> WGConfig | None:
    """Fallback aus WG_PRIVATE_KEY/WG_ADDRESS/WG_PEER_PUBLIC_KEY/WG_ENDPOINT."""
    if not all(wg_env.get(k) for k in ("WG_PRIVATE_KEY", "WG_ADDRESS", "WG_PEER_PUBLIC_KEY", "WG_ENDPOINT")):
        return None
    return parse_wg_conf(
        "[Interface]\n"
        f"PrivateKey = {wg_env['WG_PRIVATE_KEY']}\n"
        f"Address = {wg_env['WG_ADDRESS']}\n"
        "[Peer]\n"
        f"PublicKey = {wg_env['WG_PEER_PUBLIC_KEY']}\n"
        f"Endpoint = {wg_env['WG_ENDPOINT']}\n"
    )


def valid_filename(name: str) -> bool:
    """Nur [A-Za-z0-9._-]+.conf, kein führender Punkt, keine Pfadanteile."""
    return (
        isinstance(name, str)
        and len(name) <= 100
        and not name.startswith(".")
        and FILENAME_RE.fullmatch(name) is not None
    )


def normalize_paste_name(name: str) -> str:
    name = (name or "").strip()
    if name and not name.lower().endswith(".conf"):
        name += ".conf"
    return name


class ServerStore:
    """Verwaltet CONFIG_DIR/servers/*.conf und CONFIG_DIR/state.json."""

    def __init__(self, config_dir: str, wg_env: dict | None = None):
        self.config_dir = config_dir
        self.servers_dir = os.path.join(config_dir, "servers")
        self.state_file = os.path.join(config_dir, "state.json")
        self.wg_env = wg_env or {}

    def ensure_dirs(self) -> None:
        os.makedirs(self.servers_dir, exist_ok=True)

    def _path(self, name: str) -> str:
        if not valid_filename(name):
            raise ConfError(f"Ungültiger Dateiname '{name}'. Erlaubt: Buchstaben, Ziffern, . _ - und Endung .conf")
        base = os.path.realpath(self.servers_dir)
        path = os.path.realpath(os.path.join(base, name))
        if os.path.dirname(path) != base:
            raise ConfError("Ungültiger Pfad.")
        return path

    # --- Lesen -----------------------------------------------------------

    def list(self) -> list[ServerEntry]:
        """Liest das Verzeichnis jedes Mal neu ein."""
        entries: list[ServerEntry] = []
        try:
            names = sorted(os.listdir(self.servers_dir))
        except FileNotFoundError:
            names = []
        for name in names:
            if not valid_filename(name):
                continue
            path = os.path.join(self.servers_dir, name)
            if not os.path.isfile(path):
                continue
            try:
                if os.path.getsize(path) > MAX_CONF_SIZE:
                    raise ConfError("Datei ist zu groß.")
                with open(path, encoding="utf-8", errors="replace") as fh:
                    entries.append(ServerEntry(name, parse_wg_conf(fh.read())))
            except (ConfError, OSError) as e:
                entries.append(ServerEntry(name, None, str(e)))
        if not entries:
            try:
                env_cfg = config_from_env(self.wg_env)
            except ConfError as e:
                return [ServerEntry(ENV_SERVER_NAME, None, f"WG_*-Variablen: {e}")]
            if env_cfg:
                entries.append(ServerEntry(ENV_SERVER_NAME, env_cfg))
        return entries

    def get(self, name: str) -> ServerEntry | None:
        for entry in self.list():
            if entry.name == name:
                return entry
        return None

    # --- Schreiben -------------------------------------------------------

    def _write(self, name: str, content: str) -> None:
        path = self._path(name)
        self.ensure_dirs()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def save(self, name: str, content: str) -> WGConfig:
        """Prüft den Inhalt und speichert ihn mit Rechten 600."""
        if not valid_filename(name):
            raise ConfError(f"Ungültiger Dateiname '{name}'. Erlaubt: Buchstaben, Ziffern, . _ - und Endung .conf")
        if len(content.encode("utf-8")) > MAX_CONF_SIZE:
            raise ConfError("Datei ist zu groß.")
        cfg = parse_wg_conf(content)
        if not content.endswith("\n"):
            content += "\n"
        self._write(name, content)
        return cfg

    def import_zip(self, data: bytes) -> tuple[list[str], list[str]]:
        """Importiert alle gültigen .conf aus einem ZIP. Rückgabe: (importiert, übersprungen)."""
        imported, skipped = [], []
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise ConfError("Die Datei ist kein gültiges ZIP-Archiv.")
        with zf:
            members = [m for m in zf.infolist() if not m.is_dir()]
            if len(members) > MAX_ZIP_MEMBERS:
                raise ConfError("Das ZIP enthält zu viele Dateien.")
            for info in members:
                # Ordner im ZIP ignorieren, nur den Dateinamen verwenden
                name = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
                if not name.lower().endswith(".conf"):
                    continue
                if not valid_filename(name):
                    skipped.append(f"{name}: ungültiger Dateiname")
                    continue
                if info.file_size > MAX_CONF_SIZE:
                    skipped.append(f"{name}: zu groß")
                    continue
                try:
                    text = zf.read(info).decode("utf-8")
                    self.save(name, text)
                    imported.append(name)
                except (ConfError, UnicodeDecodeError) as e:
                    skipped.append(f"{name}: {e}")
        if not imported and not skipped:
            raise ConfError("Im ZIP wurde keine .conf-Datei gefunden.")
        return imported, skipped

    def delete(self, name: str) -> None:
        path = self._path(name)
        if not os.path.isfile(path):
            raise ConfError(f"Server '{name}' existiert nicht.")
        os.remove(path)

    # --- Zustand ---------------------------------------------------------

    def load_active(self) -> str | None:
        try:
            with open(self.state_file, encoding="utf-8") as fh:
                value = json.load(fh).get("active_server")
            return value if isinstance(value, str) else None
        except (OSError, ValueError, AttributeError):
            return None

    def save_active(self, name: str | None) -> None:
        self.ensure_dirs()
        tmp = self.state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"active_server": name}, fh)
        os.replace(tmp, self.state_file)
