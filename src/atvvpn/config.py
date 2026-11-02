"""Einlesen und Prüfen der Umgebungsvariablen."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

TRUE_VALUES = {"1", "true", "yes", "ja", "on"}


class SettingsError(ValueError):
    pass


@dataclass
class Settings:
    atv_ip: str
    lan_cidr: str = "192.168.178.0/24"
    lan_if: str = ""  # leer = automatisch über die Default-Route
    config_dir: str = "/config"
    wg_table: int = 51820
    wg_if: str = "wg-atv"
    web_port: int = 8099
    killswitch: bool = True
    web_password: str = ""
    auto_reset_time: str = "03:00"  # leer = deaktiviert
    auto_failover: bool = False
    tz: str = "Europe/Berlin"
    # Optionaler Fallback, falls im Volume keine .conf liegt
    wg_env: dict = field(default_factory=dict)


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in TRUE_VALUES


def parse_reset_time(value: str) -> tuple[int, int] | None:
    """'03:00' -> (3, 0); leer -> None; ungültig -> SettingsError."""
    value = (value or "").strip()
    if not value:
        return None
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", value)
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise SettingsError(f"AUTO_RESET_TIME '{value}' ist ungültig (Format HH:MM, z. B. 03:00).")
    return int(m.group(1)), int(m.group(2))


def load_settings(env: dict[str, str]) -> Settings:
    errors = []

    atv_ip = env.get("ATV_IP", "").strip()
    if not atv_ip:
        errors.append("ATV_IP ist nicht gesetzt (IP-Adresse des Apple TV, z. B. 192.168.178.123).")
    else:
        try:
            ipaddress.IPv4Address(atv_ip)
        except ValueError:
            errors.append(f"ATV_IP '{atv_ip}' ist keine gültige IPv4-Adresse.")

    lan_cidr = env.get("LAN_CIDR", "").strip() or "192.168.178.0/24"
    try:
        lan_cidr = str(ipaddress.IPv4Network(lan_cidr, strict=False))
    except ValueError:
        errors.append(f"LAN_CIDR '{lan_cidr}' ist kein gültiges IPv4-Netz (z. B. 192.168.178.0/24).")

    def _int(name: str, default: int) -> int:
        raw = env.get(name, "").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            errors.append(f"{name} '{raw}' ist keine Zahl.")
            return default

    wg_table = _int("WG_TABLE", 51820)
    web_port = _int("WEB_PORT", 8099)

    # Leerer Wert = automatisches Zurücksetzen deaktiviert
    auto_reset_time = env.get("AUTO_RESET_TIME", "03:00")
    try:
        parse_reset_time(auto_reset_time)
    except SettingsError as e:
        errors.append(str(e))

    tz = env.get("TZ", "").strip() or "Europe/Berlin"
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(tz)
    except Exception:
        errors.append(f"Zeitzone TZ '{tz}' ist unbekannt (ist tzdata installiert?).")

    if errors:
        raise SettingsError("\n".join(errors))

    wg_env = {
        k: env.get(k, "").strip()
        for k in ("WG_PRIVATE_KEY", "WG_ADDRESS", "WG_PEER_PUBLIC_KEY", "WG_ENDPOINT")
    }

    return Settings(
        atv_ip=atv_ip,
        lan_cidr=lan_cidr,
        lan_if=env.get("LAN_IF", "").strip(),
        config_dir=env.get("CONFIG_DIR", "").strip() or "/config",
        wg_table=wg_table,
        web_port=web_port,
        killswitch=_bool(env.get("KILLSWITCH"), True),
        web_password=env.get("WEB_PASSWORD", ""),
        auto_reset_time=auto_reset_time.strip(),
        auto_failover=_bool(env.get("AUTO_FAILOVER"), False),
        tz=tz,
        wg_env=wg_env,
    )
