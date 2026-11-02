import base64
import http.client
import io
import json
import threading
import zipfile

import pytest

from atvvpn.controller import Controller
from atvvpn.servers import ServerStore
from atvvpn.web import make_server

from conftest import KEY_A, KEY_C, KEY_D, conf_text

PASSWORD = "test-passwort"


@pytest.fixture
def server(settings, net, runner):
    settings.web_password = PASSWORD
    runner.set(["ip", "rule", "del"], 1)
    runner.set(["ip", "link", "show"], 1)
    for table in ("nat", "filter", "mangle"):
        runner.set(["iptables-nft", "-w", "-t", table, "-D"], 1)
    store = ServerStore(settings.config_dir)
    ctrl = Controller(settings, net, store)
    ctrl.start()
    httpd = make_server(ctrl, 0)
    httpd.server_address = ("127.0.0.1", httpd.server_address[1])
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd, ctrl
    httpd.shutdown()
    httpd.server_close()


def req(httpd, method, path, body=b"", headers=None, auth=True):
    conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=5)
    h = dict(headers or {})
    if auth:
        h["Authorization"] = "Basic " + base64.b64encode(f"admin:{PASSWORD}".encode()).decode()
    conn.request(method, path, body=body, headers=h)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp, data


def multipart(filename, content: bytes):
    boundary = "----testgrenze"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def test_healthz_without_auth(server):
    httpd, _ = server
    resp, data = req(httpd, "GET", "/healthz", auth=False)
    assert resp.status == 200 and data == b"ok"


def test_auth_required(server):
    httpd, _ = server
    resp, _ = req(httpd, "GET", "/", auth=False)
    assert resp.status == 401
    resp, data = req(httpd, "GET", "/")
    assert resp.status == 200
    assert "Deutschland (normal)" in data.decode()
    assert "Server hinzufügen" in data.decode()


def test_upload_zip_and_select(server):
    httpd, ctrl = server
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("al-tia-wg-001.conf", conf_text())
        zf.writestr("al-tia-wg-002.conf", conf_text(priv=KEY_C, pub=KEY_D, endpoint="203.0.113.12:51820"))
    body, headers = multipart("mullvad_wireguard_linux_al_tia.zip", buf.getvalue())
    resp, _ = req(httpd, "POST", "/server/upload", body, headers)
    assert resp.status == 303
    assert "2%20Server%20importiert" in resp.getheader("Location")
    assert ctrl.active == "al-tia-wg-001.conf"

    resp, data = req(httpd, "GET", "/api/servers")
    servers = json.loads(data)
    assert [s["name"] for s in servers] == ["al-tia-wg-001.conf", "al-tia-wg-002.conf"]
    assert servers[0]["active"] is True
    assert servers[0]["private_key"] == KEY_A[:4] + "…"

    # Seite zeigt den Private Key nie im Klartext
    _, page = req(httpd, "GET", "/")
    assert KEY_A not in page.decode() and KEY_C not in page.decode()

    resp, _ = req(httpd, "POST", "/server/select", b"name=al-tia-wg-002.conf",
                  {"Content-Type": "application/x-www-form-urlencoded"})
    assert resp.status == 303
    assert ctrl.active == "al-tia-wg-002.conf"


def test_upload_rejects_bad_name(server, settings):
    httpd, _ = server
    body, headers = multipart("bad name.conf", conf_text().encode())
    resp, _ = req(httpd, "POST", "/server/upload", body, headers)
    assert resp.status == 303 and "err=1" in resp.getheader("Location")


def test_paste_toggle_and_status(server):
    httpd, ctrl = server
    from urllib.parse import urlencode

    form = urlencode({"name": "al-tia-wg-003", "content": conf_text()}).encode()
    resp, _ = req(httpd, "POST", "/server/paste", form, {"Content-Type": "application/x-www-form-urlencoded"})
    assert resp.status == 303 and "err" not in resp.getheader("Location")
    assert ctrl.active == "al-tia-wg-003.conf"

    resp, _ = req(httpd, "POST", "/toggle")
    assert resp.status == 303
    resp, data = req(httpd, "GET", "/api/status")
    st = json.loads(data)
    assert st["mode"] == "al"
    _, page = req(httpd, "GET", "/")
    assert "Wird automatisch um 03:00 Uhr zurückgesetzt" in page.decode()

    resp, data = req(httpd, "POST", "/off", headers={"Accept": "application/json"})
    assert resp.status == 200 and json.loads(data)["status"]["mode"] == "de"


def test_delete_active_refused_via_web(server):
    httpd, ctrl = server
    ctrl.store.save("a.conf", conf_text())
    ctrl.refresh()
    resp, _ = req(httpd, "POST", "/server/delete", b"name=a.conf",
                  {"Content-Type": "application/x-www-form-urlencoded"})
    assert "err=1" in resp.getheader("Location")


def test_cross_origin_post_rejected(server):
    httpd, _ = server
    resp, _ = req(httpd, "POST", "/toggle", headers={"Origin": "http://evil.example"})
    assert resp.status == 403
