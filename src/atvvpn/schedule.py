"""Berechnung des nächsten Zeitpunkts für das automatische Zurücksetzen."""

from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo


def next_reset(now: datetime, hour: int, minute: int, tz: ZoneInfo) -> datetime:
    """Nächster Zeitpunkt HH:MM Ortszeit nach `now` (aware), als aware UTC-datetime.

    Berücksichtigt Sommer-/Winterzeit: Es wird je Kalendertag die lokale Uhrzeit
    gebildet und erst dann nach UTC umgerechnet. Eine Uhrzeit, die es wegen der
    Zeitumstellung nicht gibt (z. B. 02:30 im März), wird auf die Zeit nach der
    Umstellung verschoben; doppelte Uhrzeiten (Oktober) zählen beim ersten Mal.
    """
    if now.tzinfo is None:
        raise ValueError("now muss eine Zeitzone haben")
    local_now = now.astimezone(tz)
    day = local_now.date()
    for offset in range(0, 3):
        local = datetime.combine(day + timedelta(days=offset), time(hour, minute), tzinfo=tz)
        # Rundreise über UTC normalisiert nicht existierende Uhrzeiten
        candidate = local.astimezone(timezone.utc)
        if candidate > now.astimezone(timezone.utc):
            return candidate
    raise AssertionError("unerreichbar")
