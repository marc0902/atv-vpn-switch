import io
import os
import stat
import sys
import zipfile

import pytest

from atvvpn.servers import (
    ENV_SERVER_NAME,
    ConfError,
    ServerStore,
    config_from_env,
    mask_key,
    normalize_paste_name,
    parse_wg_conf,
    valid_filename,
)

from conftest import KEY_A, KEY_B, conf_text


# --- Parser ------------------------------------------------------------------

def test_parse_valid_mullvad_conf():
    cfg = parse_wg_conf(conf_text())
    assert cfg.private_key == KEY_A
    assert cfg.public_key == KEY_B
    assert cfg.address == "10.64.0.2/32"  # IPv6 ignoriert
    assert cfg.endpoint == "203.0.113.10:51820"


def test_parse_ipv6_first_and_no_prefix():
    cfg = parse_wg_conf(conf_text(addr="fc00::2/128, 10.64.0.9"))
    assert cfg.address == "10.64.0.9/32"


def test_parse_case_insensitive_and_comments():
    text = f"[interface]\nprivatekey={KEY_A}  # Kommentar\naddress=10.1.2.3/32\n[PEER]\npublickey = {KEY_B}\nendpoint = al-tia.example.net:3000\n"
    cfg = parse_wg_conf(text)
    assert cfg.endpoint == "al-tia.example.net:3000"


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("", "[Interface] fehlt"),
        (f"[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2/32\n", "[Peer] fehlt"),
        (conf_text(priv="kaputt"), "PrivateKey"),
        (conf_text(pub="AAAA"), "PublicKey"),
        (conf_text(addr="fc00::1/128"), "keine IPv4"),
        (conf_text(addr="nonsense"), "Address"),
        (conf_text(endpoint="203.0.113.10"), "Endpoint"),
        (conf_text(endpoint="203.0.113.10:99999"), "Endpoint"),
        ("PrivateKey = x\n", "außerhalb"),
        ("[Interface]\nnur text\n", "Schlüssel = Wert"),
        ("[Foo]\n", "unbekannter Abschnitt"),
        (f"[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {KEY_B}\nEndpoint = 1.2.3.4:1\n", "PrivateKey fehlt"),
    ],
)
def test_parse_broken(text, fragment):
    with pytest.raises(ConfError) as exc:
        parse_wg_conf(text)
    assert fragment in str(exc.value)


def test_mask_key():
    assert mask_key(KEY_A) == KEY_A[:4] + "…"
    assert KEY_A not in mask_key(KEY_A)


def test_config_from_env():
    assert config_from_env({}) is None
    cfg = config_from_env({
        "WG_PRIVATE_KEY": KEY_A, "WG_ADDRESS": "10.64.0.2/32",
        "WG_PEER_PUBLIC_KEY": KEY_B, "WG_ENDPOINT": "203.0.113.1:51820",
    })
    assert cfg.address == "10.64.0.2/32"


# --- Dateinamen --------------------------------------------------------------

@pytest.mark.parametrize("name", ["al-tia-wg-001.conf", "A_b.c-1.conf", "x.conf"])
def test_valid_filenames(name):
    assert valid_filename(name)


@pytest.mark.parametrize(
    "name",
    ["../evil.conf", "..\\evil.conf", "a/b.conf", "/etc/passwd", "a.conf.txt", "a b.conf",
     ".hidden.conf", "a.CONF\x00", "", "ä.conf", "x" * 200 + ".conf", "evil.conf/", "state.json"],
)
def test_invalid_filenames(name):
    assert not valid_filename(name)


def test_normalize_paste_name():
    assert normalize_paste_name(" al-tia ") == "al-tia.conf"
    assert normalize_paste_name("x.conf") == "x.conf"


# --- Store -------------------------------------------------------------------

def test_store_save_list_delete(tmp_path):
    store = ServerStore(str(tmp_path))
    store.ensure_dirs()
    store.save("al-tia-wg-001.conf", conf_text())
    (tmp_path / "servers" / "broken.conf").write_text("Unsinn")
    (tmp_path / "servers" / "readme.txt").write_text("ignorieren")
    entries = store.list()
    assert [e.name for e in entries] == ["al-tia-wg-001.conf", "broken.conf"]
    assert entries[0].valid and not entries[1].valid and entries[1].error
    store.delete("broken.conf")
    assert [e.name for e in store.list()] == ["al-tia-wg-001.conf"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-Dateirechte")
def test_store_file_mode_600(tmp_path):
    store = ServerStore(str(tmp_path))
    store.save("a.conf", conf_text())
    mode = stat.S_IMODE(os.stat(tmp_path / "servers" / "a.conf").st_mode)
    assert mode == 0o600


def test_store_rejects_traversal(tmp_path):
    store = ServerStore(str(tmp_path))
    with pytest.raises(ConfError):
        store.save("../x.conf", conf_text())
    with pytest.raises(ConfError):
        store.delete("../state.json")


def test_store_rejects_invalid_content(tmp_path):
    store = ServerStore(str(tmp_path))
    with pytest.raises(ConfError):
        store.save("a.conf", "kaputt")
    assert not (tmp_path / "servers" / "a.conf").exists()


def test_store_env_fallback_only_without_files(tmp_path):
    env = {"WG_PRIVATE_KEY": KEY_A, "WG_ADDRESS": "10.64.0.2/32",
           "WG_PEER_PUBLIC_KEY": KEY_B, "WG_ENDPOINT": "203.0.113.1:51820"}
    store = ServerStore(str(tmp_path), env)
    store.ensure_dirs()
    assert [e.name for e in store.list()] == [ENV_SERVER_NAME]
    store.save("a.conf", conf_text())
    assert [e.name for e in store.list()] == ["a.conf"]


def test_state_roundtrip(tmp_path):
    store = ServerStore(str(tmp_path))
    assert store.load_active() is None
    store.save_active("al-tia-wg-002.conf")
    assert store.load_active() == "al-tia-wg-002.conf"
    (tmp_path / "state.json").write_text("{kaputt")
    assert store.load_active() is None


# --- ZIP-Import --------------------------------------------------------------

def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_zip_import(tmp_path):
    store = ServerStore(str(tmp_path))
    data = _zip({
        "al-tia-wg-001.conf": conf_text(),
        "mullvad/al-tia-wg-002.conf": conf_text(endpoint="203.0.113.11:51820"),
        "../../evil.conf": conf_text(),  # Pfadanteile werden entfernt
        "bad name.conf": conf_text(),
        "broken.conf": "kaputt",
        "README.txt": "nicht importieren",
    })
    imported, skipped = store.import_zip(data)
    assert sorted(imported) == ["al-tia-wg-001.conf", "al-tia-wg-002.conf", "evil.conf"]
    assert any(s.startswith("bad name.conf") for s in skipped)
    assert any(s.startswith("broken.conf") for s in skipped)
    assert sorted(os.listdir(tmp_path / "servers")) == ["al-tia-wg-001.conf", "al-tia-wg-002.conf", "evil.conf"]
    assert not (tmp_path / "evil.conf").exists()


def test_zip_invalid(tmp_path):
    store = ServerStore(str(tmp_path))
    with pytest.raises(ConfError):
        store.import_zip(b"kein zip")
    with pytest.raises(ConfError):
        store.import_zip(_zip({"a.txt": "x"}))
