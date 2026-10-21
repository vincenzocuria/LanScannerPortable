import os
import struct
import sys
import time
import pathlib

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import scan_lan as s  # noqa: E402


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"


def _ptr_response(ip: str, target: str, repeat_question: bool = True) -> bytes:
    """Risposta mDNS legacy unicast: ripete la domanda e usa un puntatore di compressione."""
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    question = _dns_name(rev) + struct.pack("!HH", 12, 1)
    rdata = _dns_name(target)
    if repeat_question:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
        return struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0) + question + answer
    answer = _dns_name(rev) + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + answer


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


# --- mDNS ---

@pytest.mark.parametrize("repeat_question", [True, False])
def test_ptr_response_returns_real_name(repeat_question):
    data = _ptr_response("192.168.10.10", "mynas.local", repeat_question)
    assert s._parse_ptr_response(data) == "mynas.local"


def test_ptr_response_garbage_is_empty_or_error():
    assert s._parse_ptr_response(b"\x00" * 5) == ""
    with pytest.raises(ValueError):
        s._parse_ptr_response(struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + b"\x05abc")


def test_ptr_query_format():
    q = s._build_ptr_query("10.0.0.5")
    assert q[12:] == _dns_name("5.0.0.10.in-addr.arpa") + b"\x00\x0c\x00\x01"


# --- intervalli IP ---

def test_parse_ip_input_cidr_and_range():
    assert s._parse_ip_input("192.168.1.0/30", "") == ["192.168.1.1", "192.168.1.2"]
    assert s._parse_ip_input("10.0.0.3", "10.0.0.1") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_parse_ip_input_rejects_huge_networks_without_building_them():
    t0 = time.perf_counter()
    with pytest.raises(ValueError):
        s._parse_ip_input("10.0.0.0/8", "")
    with pytest.raises(ValueError):
        s._parse_ip_input("10.0.0.1", "10.0.255.255")
    assert time.perf_counter() - t0 < 0.5


def test_default_range_uses_prefix():
    assert s._default_range_for_ip("192.168.10.6", 24) == ("192.168.10.1", "192.168.10.254")
    assert s._default_range_for_ip("10.1.2.3", 22) == ("10.1.0.1", "10.1.3.254")
    # /16 supera il limite: si propone la /24 dell'host
    assert s._default_range_for_ip("172.16.5.9", 16) == ("172.16.5.1", "172.16.5.254")
    assert s._default_range_for_ip("non-ip") == ("192.168.1.1", "192.168.1.254")


# --- ipconfig / arp / tracert ---

IPCONFIG_IT = """
Configurazione IP di Windows

Scheda Ethernet Ethernet:

   Suffisso DNS specifico per connessione:
   Indirizzo IPv6 locale rispetto al collegamento . : fe80::1%12
   Indirizzo IPv4. . . . . . . . . . . . : 192.168.10.6
   Subnet mask . . . . . . . . . . . . . : 255.255.255.0
   Gateway predefinito . . . . . . . . . : 192.168.10.1

Scheda LAN wireless Wi-Fi:

   Stato supporto. . . . . . . . . . . . : Supporto disconnesso

Scheda Ethernet vEthernet (WSL):

   IPv4 Address. . . . . . . . . . . : 172.20.32.1
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
"""


def test_parse_ipconfig_any_language():
    assert s._parse_ipconfig(IPCONFIG_IT) == [
        ("Scheda Ethernet Ethernet", "192.168.10.6", 24),
        ("Scheda Ethernet vEthernet (WSL)", "172.20.32.1", 20),
    ]


def test_parse_arp_skips_broadcast_and_multicast():
    out = """
Interfaccia: 192.168.10.6 --- 0xc
  Indirizzo Internet    Indirizzo fisico      Tipo
  192.168.10.1          a4-91-b1-00-11-22     dinamico
  192.168.10.255        ff-ff-ff-ff-ff-ff     statico
  224.0.0.22            01-00-5e-00-00-16     statico
"""
    assert s._parse_arp(out) == {"192.168.10.1": "A4:91:B1:00:11:22"}


def test_parse_tracert_line():
    assert s._parse_tracert_line("  1    <1 ms    <1 ms    <1 ms  192.168.10.1") == (1, "192.168.10.1", 1.0)
    assert s._parse_tracert_line("  3    12 ms    14 ms     *     10.0.0.1") == (3, "10.0.0.1", 13.0)
    assert s._parse_tracert_line("  4     *        *        *     Richiesta scaduta.") is None


# --- porte, OUI, hint, SSDP ---

def test_parse_ports():
    assert s._parse_ports("22, 80,80, 0, 70000, 8000-8002, x") == [
        (22, "Porta 22"), (80, "Porta 80"), (8000, "Porta 8000"), (8001, "Porta 8001"), (8002, "Porta 8002")
    ]
    assert s._parse_ports("65534-65535") == [(65534, "Porta 65534"), (65535, "Porta 65535")]
    assert len(s._parse_ports("1-65535", max_ports=100)) == 100


def test_vendor_prefers_longest_prefix(monkeypatch):
    monkeypatch.setattr(s, "_OUI_MAP", {"001BC5": "IEEE Registration Authority", "001BC5009": "Acme IoT"})
    assert s._vendor_from_mac("00-1B-C5-00-9F-01") == "Acme IoT"
    assert s._vendor_from_mac("00:1B:C5:12:34:56") == "IEEE Registration Authority"
    assert s._vendor_from_mac("—") == ""
    assert s._vendor_from_mac("00:1B") == ""


def test_bundled_oui_database_loads():
    s._OUI_MAP = None
    m = s._load_oui_map()
    assert len(m) > 30000
    assert {len(k) for k in m} == {6, 7, 9}


def test_quick_hint_duplicate_mac_and_random():
    assert "MAC su 3 IP" in s._quick_hint("", "", "AA:BB:CC:00:00:01", mac_ip_count=3)
    assert s._quick_hint("", "", "02:00:00:00:00:01") == "MAC locale (random)"
    assert s._quick_hint("DESKTOP-ABC", "", "") == "PC Windows?"


def test_parse_ssdp_response():
    txt = "HTTP/1.1 200 OK\r\nLOCATION: http://x/desc.xml\r\nSERVER: Linux UPnP/1.0 Sonos/70\r\n\r\n"
    assert s._parse_ssdp_response(txt) == "Linux UPnP/1.0 Sonos/70"
    assert s._parse_ssdp_response("HTTP/1.1 200 OK\r\nLocation: http://x/d.xml\r\n") == "UPnP (http://x/d.xml)"


def test_update_version_compare():
    assert s.UpdateCheckerThread._is_newer("1.3.1", "1.3.0")
    assert s.UpdateCheckerThread._is_newer("1.10.0", "1.9.9")
    assert not s.UpdateCheckerThread._is_newer("1.3.0", "1.3.0")


# --- rete locale (solo Windows) ---

@pytest.mark.skipif(sys.platform != "win32", reason="API ICMP di Windows")
def test_ping_loopback_native():
    ok, rtt = s._ping_one("127.0.0.1", 500)
    assert ok and rtt >= 0
    assert s._get_icmp_api() is not None


def test_port_probe_finds_local_listener():
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        res = s._probe_ports_with_banner("127.0.0.1", [(port, "test"), (1, "chiusa")], timeout=0.3)
    finally:
        srv.close()
    assert [p for p, _, _ in res] == [port]


# --- GUI: i risultati in background arrivano davvero alla finestra ---

def _pump(app, cond, timeout=8.0):
    t0 = time.time()
    while time.time() - t0 < timeout and not cond():
        app.processEvents()
        time.sleep(0.02)
    return cond()


def test_port_scan_dialog_shows_results(app):
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        d = s.CustomPortScanDialog("127.0.0.1")
        d.txt_ports.setText(str(port))
        assert _pump(app, lambda: d.btn_scan.isEnabled())  # attende la scansione avviata nel costruttore
        d._run_scan()
        assert _pump(app, lambda: "OPEN" in d.txt_results.toPlainText())
        assert f"Porta {port}" in d.txt_results.toPlainText()
        d.reject()
    finally:
        srv.close()


def test_continuous_ping_stops_on_close(app):
    d = s.ContinuousPingDialog("127.0.0.1")
    worker = d.worker
    assert _pump(app, lambda: d.sent_count >= 1)
    d.accept()  # pulsante "Chiudi"
    assert worker.wait(3000)
    sent = d.sent_count
    _pump(app, lambda: False, timeout=1.5)
    assert d.sent_count == sent


def test_html_report_escapes_network_data(app, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog, QMessageBox, QTreeWidgetItem

    w = s.LanScannerWindow()
    QTreeWidgetItem(w.table, ["192.168.1.9", "x", "—", "—", "<script>alert(1)</script>", "—", "—"])
    out = tmp_path / "r.html"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), ""))
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    w._export_html_action()
    text = out.read_text(encoding="utf-8")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<script>alert(1)" not in text
    w.close()


# --- aggiornamento automatico ---

def test_pick_update_asset():
    release = {"assets": [
        {"name": "LanScanner_Setup_v9.exe", "browser_download_url": "https://x/setup.exe", "size": 5},
        {"name": "LanScanner.exe", "browser_download_url": "https://x/LanScanner.exe", "size": 10,
         "digest": "sha256:ABCDEF"},
    ]}
    assert s._pick_update_asset(release) == {"url": "https://x/LanScanner.exe", "size": 10, "sha256": "abcdef"}
    assert s._pick_update_asset({"assets": []}) is None


@pytest.fixture()
def http_file(tmp_path):
    import functools
    import http.server

    payload = b"MZ" + os.urandom(300_000)
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "LanScanner.exe").write_bytes(payload)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(tmp_path / "srv"))
    handler.log_message = lambda *a, **k: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    import threading

    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/LanScanner.exe", payload
    srv.shutdown()


def test_download_update_verifies_checksum(tmp_path, http_file):
    import hashlib

    url, payload = http_file
    good = {"url": url, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    seen = []
    out = s._download_update(good, tmp_path / "new.exe", progress=lambda d, t: seen.append((d, t)))
    assert out.read_bytes() == payload
    assert seen[-1] == (len(payload), len(payload))

    bad = dict(good, sha256="0" * 64)
    with pytest.raises(RuntimeError, match="SHA-256"):
        s._download_update(bad, tmp_path / "bad.exe")
    assert not (tmp_path / "bad.exe").exists() and not (tmp_path / "bad.exe.part").exists()

    with pytest.raises(RuntimeError, match="incompleto"):
        s._download_update(dict(good, size=len(payload) + 1, sha256=""), tmp_path / "short.exe")


def test_install_update_swaps_files(tmp_path):
    cur = tmp_path / "LanScanner.exe"
    new = tmp_path / "LanScanner.exe.download"
    cur.write_bytes(b"MZ-old")
    new.write_bytes(b"MZ-new")
    old = s._install_update(new, cur)
    assert cur.read_bytes() == b"MZ-new"
    assert old.read_bytes() == b"MZ-old" and old.name == "LanScanner.exe.old"
    assert not new.exists()


# --- MAC su più IP ---

def test_scan_marks_previous_dhcp_ip_not_conflict(app, monkeypatch):
    mac = "A0:48:1C:76:C1:C8"
    monkeypatch.setattr(s, "_arp_map", lambda: {"192.168.0.33": mac, "192.168.0.20": mac})
    monkeypatch.setattr(s, "_ping_one", lambda ip, t=750: (ip == "192.168.0.33", 1.0))
    monkeypatch.setattr(s, "_resolve_hostname", lambda ip: "DESKTOP-9LIEEHL")
    monkeypatch.setattr(s.time, "sleep", lambda x: None)
    w = s.ScanWorkerThread(["192.168.0.20", "192.168.0.33"], {})
    hints = {}
    w.hostname_resolved.connect(lambda ip, hn, hint, note: hints.__setitem__(ip, hint))
    w.run()
    assert "MAC su" not in hints["192.168.0.33"]
    assert hints["192.168.0.20"].startswith("IP precedente di 192.168.0.33?")


def test_scan_flags_two_alive_ips_with_same_mac(app, monkeypatch):
    mac = "A0:48:1C:76:C1:C8"
    monkeypatch.setattr(s, "_arp_map", lambda: {"10.0.0.1": mac, "10.0.0.2": mac})
    monkeypatch.setattr(s, "_ping_one", lambda ip, t=750: (True, 1.0))
    monkeypatch.setattr(s, "_resolve_hostname", lambda ip: "")
    monkeypatch.setattr(s, "_resolve_mdns_name", lambda ip: "")
    monkeypatch.setattr(s, "_probe_ssdp_info", lambda ip: "")
    monkeypatch.setattr(s.time, "sleep", lambda x: None)
    w = s.ScanWorkerThread(["10.0.0.1", "10.0.0.2"], {})
    hints = {}
    w.hostname_resolved.connect(lambda ip, hn, hint, note: hints.__setitem__(ip, hint))
    w.run()
    assert all("MAC su 2 IP attivi" in h for h in hints.values())
