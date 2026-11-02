from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from atvvpn.config import SettingsError, parse_reset_time
from atvvpn.schedule import next_reset

BERLIN = ZoneInfo("Europe/Berlin")


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


def test_same_day_before_time():
    now = datetime(2026, 1, 10, 1, 0, tzinfo=BERLIN)
    assert next_reset(now, 3, 0, BERLIN) == utc(2026, 1, 10, 2, 0)  # Winterzeit UTC+1


def test_after_time_goes_to_next_day():
    now = datetime(2026, 7, 10, 3, 0, tzinfo=BERLIN)  # genau 03:00 -> morgen
    assert next_reset(now, 3, 0, BERLIN) == utc(2026, 7, 11, 1, 0)  # Sommerzeit UTC+2


def test_across_spring_forward():
    # 29.03.2026: 02:00 -> 03:00 (Sommerzeit beginnt)
    now = datetime(2026, 3, 28, 12, 0, tzinfo=BERLIN)
    nxt = next_reset(now, 3, 0, BERLIN)
    assert nxt == utc(2026, 3, 29, 1, 0)
    assert nxt.astimezone(BERLIN).hour == 3
    # 12:00 MEZ (11:00 UTC) bis 03:00 MESZ (01:00 UTC) = 14 echte Stunden
    assert (nxt - now).total_seconds() == 14 * 3600


def test_across_fall_back():
    # 25.10.2026: 03:00 -> 02:00 (Winterzeit beginnt)
    now = datetime(2026, 10, 24, 12, 0, tzinfo=BERLIN)  # 10:00 UTC (Sommerzeit)
    nxt = next_reset(now, 3, 0, BERLIN)
    assert nxt == utc(2026, 10, 25, 2, 0)  # 03:00 MEZ
    assert nxt.astimezone(BERLIN).strftime("%H:%M") == "03:00"
    assert (nxt - now).total_seconds() == 16 * 3600


def test_nonexistent_local_time_is_shifted():
    # 02:30 existiert am 29.03.2026 nicht -> nach der Umstellung
    now = datetime(2026, 3, 29, 0, 0, tzinfo=BERLIN)
    nxt = next_reset(now, 2, 30, BERLIN)
    assert nxt > now.astimezone(timezone.utc)
    assert nxt.date() == datetime(2026, 3, 29).date()


def test_ambiguous_time_first_occurrence():
    # 02:30 kommt am 25.10.2026 zweimal vor -> erstes Mal (Sommerzeit, 00:30 UTC)
    now = datetime(2026, 10, 25, 0, 0, tzinfo=BERLIN)
    assert next_reset(now, 2, 30, BERLIN) == utc(2026, 10, 25, 0, 30)


def test_works_with_utc_now():
    now = utc(2026, 11, 2, 1, 59)  # 02:59 MEZ
    assert next_reset(now, 3, 0, BERLIN) == utc(2026, 11, 2, 2, 0)


def test_naive_rejected():
    with pytest.raises(ValueError):
        next_reset(datetime(2026, 1, 1), 3, 0, BERLIN)


def test_parse_reset_time():
    assert parse_reset_time("03:00") == (3, 0)
    assert parse_reset_time("7:05") == (7, 5)
    assert parse_reset_time("") is None
    assert parse_reset_time("  ") is None
    for bad in ("24:00", "3", "03:60", "abc"):
        with pytest.raises(SettingsError):
            parse_reset_time(bad)
