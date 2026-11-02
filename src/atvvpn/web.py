"""Weboberfläche und JSON-API (nur Standardbibliothek)."""

from __future__ import annotations

import base64
import hmac
import json
import logging
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

from .controller import MODE_AL, MODE_DE, Controller, UserError
from .multipart import parse_multipart
from .servers import ENV_SERVER_NAME, ConfError, normalize_paste_name

log = logging.getLogger(__name__)

MAX_BODY = 10 * 1024 * 1024

CSS = """
:root{color-scheme:dark;--bg:#0f1115;--card:#181b22;--line:#2a2f3a;--text:#e7e9ee;--muted:#9aa3b2;
--de:#3b82f6;--al:#e11d48;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:640px;margin:0 auto;padding:16px}
h1{font-size:1.25rem;margin:8px 0 16px;color:var(--muted);font-weight:600}
h2{font-size:1.05rem;margin:0 0 12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:16px}
.mode{font-size:1.6rem;font-weight:700;margin:4px 0 8px}
.row{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-top:1px solid var(--line);flex-wrap:wrap}
.row:first-of-type{border-top:0}
.muted{color:var(--muted)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
.ok{background:var(--ok)}.bad{background:var(--err)}.idle{background:var(--muted)}
button,.btn{font:inherit;border:0;border-radius:10px;padding:10px 14px;cursor:pointer;color:#fff;background:#334155}
button:hover{filter:brightness(1.15)}
.big{display:block;width:100%;font-size:1.25rem;font-weight:700;padding:18px;margin:12px 0 8px}
.to-al{background:var(--al)}.to-de{background:var(--de)}
.hint{color:var(--warn);font-size:.95rem;margin:6px 0 0}
.msg{padding:10px 14px;border-radius:10px;margin-bottom:16px;background:#14301f;border:1px solid #1f6b3a}
.msg.err{background:#3a1416;border-color:#7f1d1d}
table{width:100%;border-collapse:collapse}
td{padding:8px 4px;border-top:1px solid var(--line);vertical-align:middle}
tr:first-child td{border-top:0}
td.act{text-align:right;white-space:nowrap}
.tag{font-size:.8rem;padding:2px 8px;border-radius:999px;background:#14301f;color:var(--ok);border:1px solid #1f6b3a}
.tag.err{background:#3a1416;color:#fca5a5;border-color:#7f1d1d}
.small{font-size:.85rem}
.del{background:#4b1d22}
input[type=text],textarea,input[type=file]{width:100%;font:inherit;color:var(--text);background:#0f1115;
border:1px solid var(--line);border-radius:10px;padding:10px}
textarea{min-height:140px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem}
form.stack>*{margin-bottom:10px}
.inline{display:inline}
details summary{cursor:pointer;color:var(--muted);margin:8px 0}
"""


def _fmt_age(age: int | None) -> str:
    if age is None:
        return "noch kein Handshake"
    if age < 120:
        return f"vor {age} s"
    if age < 7200:
        return f"vor {age // 60} min"
    return f"vor {age // 3600} h"


def render_page(ctrl: Controller, msg: str = "", err: bool = False) -> str:
    st = ctrl.status()
    servers = ctrl.store.list()
    is_al = st["mode"] == MODE_AL
    e = escape

    if st["active_server"] is None:
        tunnel = '<span class="dot idle"></span>kein Server'
    elif st["tunnel_connected"]:
        tunnel = f'<span class="dot ok"></span>verbunden ({_fmt_age(st["handshake_age_seconds"])})'
    else:
        tunnel = f'<span class="dot bad"></span>nicht verbunden ({_fmt_age(st["handshake_age_seconds"])})'

    parts = [f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Apple TV VPN</title><style>{CSS}</style></head><body><main>
<h1>Apple TV VPN-Schalter</h1>"""]
    if msg:
        parts.append(f'<div class="msg{" err" if err else ""}">{e(msg)}</div>')

    btn_cls, btn_txt, action = (
        ("to-de", "Auf 🇩🇪 Deutschland umschalten", "/off") if is_al
        else ("to-al", "Auf 🇦🇱 Albanien umschalten", "/on")
    )
    disabled = "" if (is_al or st["active_server"]) else " disabled"
    parts.append(f"""<section class="card">
<div class="muted small">Aktueller Modus</div>
<div class="mode">{e(st["mode_label"])}</div>
<form method="post" action="{action}"><button class="big {btn_cls}"{disabled}>{btn_txt}</button></form>
<p class="hint">Nach dem Umschalten YouTube-App neu starten.</p>""")
    if is_al and st["auto_reset_time"]:
        parts.append(f'<p class="hint">Wird automatisch um {e(st["auto_reset_time"])} Uhr zurückgesetzt.</p>')
    if not st["active_server"]:
        parts.append('<p class="hint">Noch kein VPN-Server vorhanden – bitte unten einen Server hinzufügen.</p>')
    parts.append(f"""<div style="margin-top:12px">
<div class="row"><span class="muted">Tunnel</span><span>{tunnel}</span></div>
<div class="row"><span class="muted">Aktiver Server</span><span>{e(st["active_server"] or "–")}
{f'<span class="muted small">({e(st["active_endpoint"])})</span>' if st["active_endpoint"] else ""}</span></div>
<div class="row"><span class="muted">Apple TV</span><span>{e(st["atv_ip"])}</span></div>
<div class="row"><span class="muted">Kill-Switch</span><span>{"an" if st["killswitch"] else "aus"}</span></div>
<div class="row"><span class="muted">Automatisch zurücksetzen</span><span>{e(st["auto_reset_time"] + " Uhr") if st["auto_reset_time"] else "aus"}</span></div>
</div></section>""")

    # Serverliste
    parts.append('<section class="card"><h2>Server</h2>')
    if st["active_missing"]:
        parts.append(f'<p class="hint">Die Datei des aktiven Servers ({e(st["active_server"])}) fehlt. Die bisherige Verbindung läuft weiter.</p>')
    if servers:
        parts.append("<table>")
        for s in servers:
            active = s.name == st["active_server"]
            if s.valid:
                info = f'<div class="muted small">{e(s.config.endpoint)} · Key {e(s.config.private_key_hint)}</div>'
            else:
                info = f'<div class="small"><span class="tag err">fehlerhaft</span> <span class="muted">{e(s.error)}</span></div>'
            actions = []
            if active:
                actions.append('<span class="tag">aktiv</span>')
            elif s.valid:
                actions.append(f'<form class="inline" method="post" action="/server/select">'
                               f'<input type="hidden" name="name" value="{e(s.name)}"><button>Verwenden</button></form>')
            if not active and s.name != ENV_SERVER_NAME:
                actions.append(f'<form class="inline" method="post" action="/server/delete" '
                               f'onsubmit="return confirm(\'{e(s.name)} löschen?\')">'
                               f'<input type="hidden" name="name" value="{e(s.name)}"><button class="del" title="Löschen">✕</button></form>')
            parts.append(f'<tr><td><div>{e(s.name)}</div>{info}</td><td class="act">{" ".join(actions)}</td></tr>')
        parts.append("</table>")
    else:
        parts.append('<p class="muted">Keine Server gefunden. Lade die Mullvad-Konfiguration (.zip oder .conf) hoch.</p>')
    parts.append("""<form method="post" action="/server/reload" style="margin-top:12px"><button>Neu einlesen</button></form>
</section>
<section class="card"><h2>Server hinzufügen</h2>
<form class="stack" method="post" action="/server/upload" enctype="multipart/form-data">
<label class="muted small">Mullvad-ZIP (alle Server) oder einzelne .conf-Datei</label>
<input type="file" name="file" accept=".zip,.conf" required>
<button>Hochladen</button></form>
<details><summary>Inhalt einer .conf einfügen</summary>
<form class="stack" method="post" action="/server/paste">
<input type="text" name="name" placeholder="Name, z. B. al-tia-wg-001.conf" pattern="[A-Za-z0-9._\\-]+" required>
<textarea name="content" placeholder="[Interface]&#10;PrivateKey = …&#10;Address = …&#10;&#10;[Peer]&#10;PublicKey = …&#10;Endpoint = …" required></textarea>
<button>Speichern</button></form></details>
</section>
<p class="muted small">Port nicht ins Internet freigeben. API: <a style="color:inherit" href="/api/status">/api/status</a></p>
</main></body></html>""")
    return "".join(parts)


def server_json(ctrl: Controller) -> list[dict]:
    out = []
    for s in ctrl.store.list():
        out.append({
            "name": s.name,
            "valid": s.valid,
            "error": s.error or None,
            "endpoint": s.config.endpoint if s.valid else None,
            "address": s.config.address if s.valid else None,
            "public_key": s.config.public_key if s.valid else None,
            "private_key": s.config.private_key_hint if s.valid else None,
            "active": s.name == ctrl.active,
        })
    return out


def make_handler(ctrl: Controller):
    password = ctrl.s.web_password

    class Handler(BaseHTTPRequestHandler):
        server_version = "atv-vpn-switch"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            log.debug("%s - %s", self.address_string(), fmt % args)

        # --- Hilfen ---

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, data, code: int = 200):
            self._send(code, json.dumps(data, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _wants_json(self) -> bool:
            return "application/json" in self.headers.get("Accept", "")

        def _redirect(self, msg: str = "", err: bool = False):
            if self._wants_json():
                return self._json({"ok": not err, "message": msg, "status": ctrl.status()}, 400 if err else 200)
            loc = "/"
            if msg:
                loc += "?msg=" + quote(msg) + ("&err=1" if err else "")
            self._send(303, b"", "text/plain", {"Location": loc})

        def _authorized(self) -> bool:
            if not password:
                return True
            header = self.headers.get("Authorization", "")
            if header.startswith("Basic "):
                try:
                    _, _, pw = base64.b64decode(header[6:]).decode("utf-8").partition(":")
                except Exception:
                    pw = ""
                if hmac.compare_digest(pw.encode(), password.encode()):
                    return True
            self._send(401, "Anmeldung erforderlich".encode(), "text/plain; charset=utf-8",
                       {"WWW-Authenticate": 'Basic realm="ATV VPN", charset="UTF-8"'})
            return False

        def _same_origin(self) -> bool:
            """Einfacher CSRF-Schutz: fremde Origin-Header ablehnen."""
            origin = self.headers.get("Origin")
            if not origin or origin == "null":
                return origin is None
            return urlparse(origin).netloc == self.headers.get("Host", "")

        def _read_body(self) -> None:
            """Liest den Body genau einmal (auch bei Fehlern, wegen Keep-Alive)."""
            self._raw = b""
            self._too_large = False
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length > MAX_BODY:
                self._too_large = True
                self.close_connection = True
                return
            if length > 0:
                self._raw = self.rfile.read(length)

        def _body(self) -> bytes:
            if self._too_large:
                raise UserError("Upload ist zu groß (max. 10 MB).")
            return self._raw

        def _form(self) -> dict[str, str]:
            data = parse_qs(self._body().decode("utf-8", errors="replace"))
            return {k: v[0] for k, v in data.items()}

        # --- GET ---

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/healthz":
                return self._send(200, b"ok", "text/plain")
            if not self._authorized():
                return
            if url.path == "/":
                ctrl.refresh()
                q = parse_qs(url.query)
                html = render_page(ctrl, q.get("msg", [""])[0], q.get("err", ["0"])[0] == "1")
                return self._send(200, html.encode(), "text/html; charset=utf-8")
            if url.path == "/api/status":
                return self._json(ctrl.status())
            if url.path == "/api/servers":
                ctrl.refresh()
                return self._json(server_json(ctrl))
            self._send(404, b"Nicht gefunden", "text/plain; charset=utf-8")

        # --- POST ---

        def do_POST(self):
            path = urlparse(self.path).path
            self._read_body()
            if not self._authorized():
                return
            if not self._same_origin():
                return self._send(403, b"Fremde Herkunft abgelehnt", "text/plain; charset=utf-8")
            try:
                msg = self._post(path)
                if msg is None:
                    return self._send(404, b"Nicht gefunden", "text/plain; charset=utf-8")
                self._redirect(msg)
            except (UserError, ConfError) as e:
                self._redirect(str(e), err=True)
            except Exception as e:  # nie den Server abstürzen lassen
                log.exception("Fehler bei %s", path)
                self._redirect(f"Interner Fehler: {e}", err=True)

        def _post(self, path: str) -> str | None:
            if path == "/toggle":
                ctrl.toggle()
                return "Umgeschaltet: " + ctrl.status()["mode_label"]
            if path == "/on":
                ctrl.set_mode(MODE_AL)
                return "Albanien aktiv"
            if path == "/off":
                ctrl.set_mode(MODE_DE)
                return "Deutschland aktiv"
            if path == "/server/reload":
                ctrl.refresh()
                return "Serverliste neu eingelesen"
            if path == "/server/select":
                name = self._form().get("name", "")
                ctrl.select_server(name)
                return f"Server {name} ist jetzt aktiv"
            if path == "/server/delete":
                name = self._form().get("name", "")
                ctrl.delete_server(name)
                return f"Server {name} gelöscht"
            if path == "/server/paste":
                form = self._form()
                name = normalize_paste_name(form.get("name", ""))
                ctrl.store.save(name, form.get("content", "").replace("\r\n", "\n"))
                log.info("Server %s per Einfügen gespeichert", name)
                ctrl.after_write([name])
                return f"Server {name} gespeichert"
            if path == "/server/upload":
                try:
                    parts = parse_multipart(self.headers.get("Content-Type", ""), self._body())
                except ValueError as e:
                    raise UserError(f"Upload fehlgeschlagen: {e}")
                f = parts.get("file")
                if not f or not f.filename or not f.data:
                    raise UserError("Keine Datei ausgewählt.")
                fname = f.filename.replace("\\", "/").rsplit("/", 1)[-1]
                if fname.lower().endswith(".zip"):
                    imported, skipped = ctrl.store.import_zip(f.data)
                    log.info("ZIP importiert: %d Server, %d übersprungen", len(imported), len(skipped))
                    ctrl.after_write(imported)
                    text = f"{len(imported)} Server importiert"
                    if skipped:
                        text += f", übersprungen: {'; '.join(skipped)}"
                    return text
                if fname.lower().endswith(".conf"):
                    ctrl.store.save(fname, f.data.decode("utf-8", errors="replace").replace("\r\n", "\n"))
                    log.info("Server %s hochgeladen", fname)
                    ctrl.after_write([fname])
                    return f"Server {fname} gespeichert"
                raise UserError("Nur .zip- oder .conf-Dateien sind erlaubt.")
            return None

    return Handler


def make_server(ctrl: Controller, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("0.0.0.0", port), make_handler(ctrl))
    httpd.daemon_threads = True
    return httpd
