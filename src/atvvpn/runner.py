"""Ausführen von Shell-Befehlen – austauschbar, damit Tests ohne Root laufen."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class Result:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner:
    """Führt Befehle als Liste (ohne Shell) aus."""

    def run(self, cmd: list[str], check: bool = True, input: str | None = None) -> Result:
        try:
            proc = subprocess.run(
                cmd, input=input, capture_output=True, text=True, timeout=30
            )
            res = Result(proc.returncode, proc.stdout, proc.stderr)
        except FileNotFoundError:
            res = Result(127, "", f"Befehl nicht gefunden: {cmd[0]}")
        except subprocess.TimeoutExpired:
            res = Result(124, "", f"Zeitüberschreitung: {' '.join(cmd)}")
        if not res.ok:
            msg = f"Befehl fehlgeschlagen ({res.returncode}): {' '.join(cmd)}: {res.stderr.strip()}"
            if check:
                raise CommandError(msg)
            log.debug(msg)
        return res


class CommandError(RuntimeError):
    pass
