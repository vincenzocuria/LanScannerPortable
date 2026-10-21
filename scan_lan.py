# -*- coding: utf-8 -*-
"""
LanScanner — Network Scanner Portatile per Windows.
Design Material 3 con PySide6 (Qt 6).
Autore: Vincenzo Curia (vcuria.app) — NGV Group S.R.L.
"""

from __future__ import annotations

import concurrent.futures
import csv
import ctypes
import ctypes.wintypes
import hashlib
import html
import ipaddress
import json
import os
import pathlib
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import winreg
import zlib
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import (
    QSettings,
    QThread,
    QTimer,
    QUrl,
    Qt,
    Signal,
    Slot,
)
from PySide6.QtGui import (
    QAction,
    QActionGroup,
    QDesktopServices,
    QFont,
    QIcon,
    QKeySequence,
)
from PySide6.QtPrintSupport import QPrintDialog, QPrinter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "LanScanner"
APP_VERSION = "1.3.2"
APP_COMPANY = "NGV Group S.R.L."
APP_DEVELOPER = "Vincenzo Curia"
GITHUB_REPO = "vincenzocuria/LanScannerPortable"
WEBSITE_URL = "https://vcuria.app"

COLS = ("ip", "ping", "mac", "vendor", "host", "hint", "note")
COL_HEADERS = ["IP", "Stato Ping / Rilevamento", "MAC", "Vendor (OUI)", "Hostname", "Indizio / Tipo", "Note Utente"]
COL_WIDTHS = [125, 165, 140, 190, 190, 160, 150]

_OUI_LOCK = threading.Lock()
_OUI_MAP: Optional[Dict[str, str]] = None


# --- RESOURCE & NETWORK UTILITIES ---

def _resource_dir() -> pathlib.Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return pathlib.Path(sys._MEIPASS)
    return pathlib.Path(__file__).resolve().parent


def _set_window_icon(w: QWidget) -> None:
    path_ico = _resource_dir() / "app_icon.ico"
    path_png = _resource_dir() / "app_icon.png"
    if path_ico.is_file():
        w.setWindowIcon(QIcon(str(path_ico)))
    elif path_png.is_file():
        w.setWindowIcon(QIcon(str(path_png)))


def _load_oui_map() -> Dict[str, str]:
    global _OUI_MAP
    with _OUI_LOCK:
        if _OUI_MAP is None:
            path = _resource_dir() / "oui_vendor.zlib"
            m: Dict[str, str] = {}
            if path.is_file():
                try:
                    raw = zlib.decompress(path.read_bytes())
                    for line in raw.decode("utf-8").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        oui, _, name = line.partition("\t")
                        oui = oui.strip().upper()
                        # 6 cifre esadecimali = MA-L (/24), 7 = MA-M (/28), 9 = MA-S (/36)
                        if len(oui) in _OUI_PREFIX_LENGTHS:
                            m[oui] = name.strip()
                except Exception:
                    m = {}
            _OUI_MAP = m
        return _OUI_MAP


_OUI_PREFIX_LENGTHS = (9, 7, 6)


def _vendor_from_mac(mac: str) -> str:
    if not mac or mac == "—":
        return ""
    hex_mac = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(hex_mac) != 12:
        return ""
    oui_map = _load_oui_map()
    # Prefisso più lungo prima: i blocchi MA-M/MA-S sono assegnati a produttori diversi dal titolare del /24
    for n in _OUI_PREFIX_LENGTHS:
        vendor = oui_map.get(hex_mac[:n])
        if vendor:
            return vendor
    return ""


def _quick_hint(
    hostname: str,
    vendor: str,
    mac: str,
    mdns: str = "",
    ssdp: str = "",
    mac_ip_count: int = 0,
    previous_ip_of: str = "",
) -> str:
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    m_info = (mdns or "").lower()
    s_info = (ssdp or "").lower()
    if h in ("", "—", "..."):
        h = ""

    hints: List[str] = []

    if previous_ip_of:
        hints.append(f"IP precedente di {previous_ip_of}?")
    if mac_ip_count > 1:
        # Due IP attivi con lo stesso MAC: conflitto, proxy ARP o un dispositivo con più indirizzi
        hints.append(f"⚠️ MAC su {mac_ip_count} IP attivi")

    if ssdp:
        hints.append(f"UPnP: {ssdp[:24]}")

    if "vmware" in v or "virtualbox" in v or "pcs systemtechnik" in v:
        hints.append("VM")
    if "raspberry" in v or "espressif" in v or "esp32" in m_info:
        hints.append("SBC/IoT")
    if "apple" in v or "iphone" in h or "ipad" in h or "macbook" in h:
        hints.append("Apple?")
    if "samsung" in v or "xiaomi" in v or "oneplus" in v or "tizen" in s_info:
        hints.append("Mobile/TV?")
    if "amazon" in v or "echo" in h or "firetv" in h:
        hints.append("Amazon/IoT?")
    if "philips" in v or "hue" in h:
        hints.append("Hue/IoT?")
    if h.startswith("desk") or "win-" in h or "desktop-" in h:
        hints.append("PC Windows?")
    if "android" in h:
        hints.append("Android?")
    if "chromecast" in h or "gw-" in h or "googlecast" in m_info:
        hints.append("Google Cast?")
    if "printer" in h or "print" in h or "ipp" in m_info:
        hints.append("Stampante?")
    if "synology" in v or "qnap" in v or "diskstation" in h:
        hints.append("NAS Storage?")

    if not hints and mac and mac != "—":
        try:
            parts = mac.upper().replace("-", ":").split(":")
            if parts and (int(parts[0], 16) & 2):
                hints.append("MAC locale (random)")
        except (ValueError, IndexError):
            pass

    return " · ".join(dict.fromkeys(hints)) if hints else "—"


def _local_ipv4() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.25)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


MAX_SCAN_HOSTS = 4096

_IPV4_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def _console_encoding() -> str:
    """Codepage OEM della console: è quella usata da ipconfig, arp, tracert e nbtstat."""
    if sys.platform == "win32":
        try:
            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            pass
    return "cp850"


def _run_console(cmd: List[str], timeout: float) -> str:
    cr = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding=_console_encoding(),
        errors="replace",
        creationflags=cr,
        timeout=timeout,
    )
    return (r.stdout or "") + (r.stderr or "")


def _parse_ipconfig(output: str) -> List[Tuple[str, str, int]]:
    """Estrae (scheda, IPv4, prefisso) dall'output di ipconfig in qualsiasi lingua.

    Le intestazioni delle schede sono le righe non indentate che terminano con ":";
    la maschera è il primo indirizzo che inizia con 255. dopo la riga IPv4.
    """
    interfaces: List[Tuple[str, str, int]] = []
    adapter = "Scheda di rete"
    pending_ip: Optional[str] = None
    for line in output.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            adapter = line.rstrip()[:-1].strip()
            pending_ip = None
            continue
        m = _IPV4_RE.search(line)
        if not m:
            continue
        addr = m.group(1)
        if pending_ip is None and "IPv4" in line:
            pending_ip = addr
        elif pending_ip is not None and addr.startswith("255."):
            try:
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{addr}").prefixlen
            except ValueError:
                prefix = 24
            if not pending_ip.startswith(("127.", "169.254.")):
                interfaces.append((adapter, pending_ip, prefix))
            pending_ip = None
    return interfaces


def _get_network_interfaces() -> List[Tuple[str, str, int]]:
    """Restituisce l'elenco delle schede di rete attive sul sistema (Nome, IP, prefisso)."""
    interfaces: List[Tuple[str, str, int]] = []
    try:
        interfaces = _parse_ipconfig(_run_console(["ipconfig"], timeout=5))
    except Exception:
        pass

    if not interfaces:
        local_ip = _local_ipv4()
        if local_ip:
            interfaces.append(("Scheda Predefinita", local_ip, 24))
    return interfaces


def _default_range_for_ip(ip: str, prefix: int = 24) -> Tuple[str, str]:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return "192.168.1.1", "192.168.1.254"
    net = ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False)
    # Reti troppo grandi (es. /16): si propone la /24 dell'host, entro il limite di scansione
    if net.num_addresses - 2 > MAX_SCAN_HOSTS or prefix > 30:
        net = ipaddress.IPv4Network(f"{addr}/24", strict=False)
    return str(net.network_address + 1), str(net.broadcast_address - 1)


def _default_range() -> Tuple[str, str]:
    local_ip = _local_ipv4() or ""
    for _name, ip, prefix in _get_network_interfaces():
        if ip == local_ip:
            return _default_range_for_ip(ip, prefix)
    return _default_range_for_ip(local_ip)


def _parse_ip_input(start_ip: str, end_ip: str) -> List[str]:
    """Interpreta l'input sia in sintassi CIDR (es. 192.168.1.0/24) che range (192.168.1.1 - 254)."""
    s = start_ip.strip()
    e = end_ip.strip()

    if "/" in s:
        net = ipaddress.IPv4Network(s, strict=False)
        # Controllo prima di generare la lista: una /8 sarebbero 16 milioni di stringhe
        if net.num_addresses - 2 > MAX_SCAN_HOSTS:
            raise ValueError(f"la rete {net} contiene troppi indirizzi (massimo {MAX_SCAN_HOSTS})")
        return [str(h) for h in net.hosts()]

    a, b = ipaddress.IPv4Address(s), ipaddress.IPv4Address(e)
    if int(a) > int(b):
        a, b = b, a
    if int(b) - int(a) + 1 > MAX_SCAN_HOSTS:
        raise ValueError(f"l'intervallo contiene troppi indirizzi (massimo {MAX_SCAN_HOSTS})")
    return [str(ipaddress.IPv4Address(i)) for i in range(int(a), int(b) + 1)]


def _ping_subprocess(ip: str, timeout_ms: int) -> Tuple[bool, float]:
    """Ping ICMP fallback tramite subprocess ping.exe."""
    t0 = time.perf_counter()
    try:
        cr = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=cr,
            timeout=max(2, timeout_ms // 500 + 3),
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if r.returncode != 0:
            return False, 0.0

        out = (r.stdout or "") + (r.stderr or "")
        if "TTL=" in out.upper():
            m = re.search(r"(?:durata|tempo|time)[=<](\d+)ms", out, re.IGNORECASE)
            if m:
                return True, float(m.group(1))
            return True, round(elapsed_ms, 1)
        return False, 0.0
    except (OSError, subprocess.TimeoutExpired):
        return False, 0.0


_INVALID_HANDLE = ctypes.c_void_p(-1).value
_ICMP_LOCK = threading.Lock()
_icmp_api: Optional[Any] = None
_icmp_api_ready = False


def _get_icmp_api() -> Optional[Any]:
    """Carica iphlpapi con i prototipi corretti: senza restype HANDLE verrebbe troncato a 32 bit."""
    global _icmp_api, _icmp_api_ready
    with _ICMP_LOCK:
        if _icmp_api_ready:
            return _icmp_api
        _icmp_api_ready = True
        if sys.platform == "win32":
            try:
                api = ctypes.WinDLL("iphlpapi.dll")
                api.IcmpCreateFile.restype = ctypes.wintypes.HANDLE
                api.IcmpCreateFile.argtypes = []
                api.IcmpCloseHandle.restype = ctypes.wintypes.BOOL
                api.IcmpCloseHandle.argtypes = [ctypes.wintypes.HANDLE]
                api.IcmpSendEcho.restype = ctypes.wintypes.DWORD
                api.IcmpSendEcho.argtypes = [
                    ctypes.wintypes.HANDLE,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.wintypes.WORD,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.wintypes.DWORD,
                    ctypes.wintypes.DWORD,
                ]
                _icmp_api = api
            except (OSError, AttributeError):
                _icmp_api = None
    return _icmp_api


def _ping_one(ip: str, timeout_ms: int = 750) -> Tuple[bool, float]:
    """Effettua un ping ICMP nativo ad alta velocità via Windows IcmpSendEcho API (ctypes).
    Passa automaticamente al fallback subprocess ping.exe se l'API non è disponibile.
    """
    api = _get_icmp_api()
    if api is None:
        return _ping_subprocess(ip, timeout_ms)

    try:
        # IPAddr è in ordine di rete: i 4 byte di inet_aton letti come intero nativo
        dest_ip = struct.unpack("=I", socket.inet_aton(ip))[0]
    except OSError:
        return False, 0.0

    icmp = api.IcmpCreateFile()
    if not icmp or icmp == _INVALID_HANDLE:
        return _ping_subprocess(ip, timeout_ms)
    try:
        send_data = ctypes.create_string_buffer(b"LanScannerPing", 14)
        # ICMP_ECHO_REPLY (40 byte su x64) + dati + 8 byte per un eventuale errore ICMP
        reply_size = ctypes.sizeof(ctypes.c_void_p) * 2 + 24 + len(send_data) + 8
        reply_buffer = ctypes.create_string_buffer(reply_size)
        res = api.IcmpSendEcho(icmp, dest_ip, send_data, len(send_data), None, reply_buffer, reply_size, timeout_ms)
        if res > 0:
            status, rtt_ms = struct.unpack_from("<II", reply_buffer.raw, 4)
            if status == 0:  # IP_SUCCESS
                return True, float(rtt_ms)
        return False, 0.0
    except Exception:
        return _ping_subprocess(ip, timeout_ms)
    finally:
        api.IcmpCloseHandle(icmp)


_ARP_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")


def _parse_arp(output: str) -> Dict[str, str]:
    m: Dict[str, str] = {}
    for line in output.splitlines():
        for x in _ARP_REGEX.finditer(line):
            ip_s, md = x.group(1), x.group(2).upper().replace("-", ":")
            # Broadcast e multicast (01:00:5E…, 33:33…) non sono dispositivi
            if md == "FF:FF:FF:FF:FF:FF" or int(md[:2], 16) & 1:
                continue
            m[ip_s] = md
    return m


def _arp_map() -> Dict[str, str]:
    try:
        return _parse_arp(_run_console(["arp", "-a"], timeout=30))
    except (OSError, subprocess.TimeoutExpired):
        return {}


def _send_wol(mac: str) -> bool:
    """Invia un pacchetto WoL Magic Packet in broadcast UDP alla porta 9 per il MAC specificato."""
    try:
        clean_mac = mac.replace(":", "").replace("-", "").replace(" ", "").upper()
        if len(clean_mac) != 12:
            return False
        data = bytes.fromhex("FF" * 6 + clean_mac * 16)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(data, ("255.255.255.255", 9))
        sock.close()
        return True
    except Exception:
        return False


def _resolve_hostname(ip: str) -> str:
    try:
        n, _, _ = socket.gethostbyaddr(ip)
        return n or ""
    except OSError:
        return ""


def _dns_read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Legge un nome DNS (con puntatori di compressione) e restituisce (nome, offset dopo il nome)."""
    labels: List[str] = []
    end_offset: Optional[int] = None
    jumps = 0
    while True:
        if offset >= len(data):
            raise ValueError("nome DNS troncato")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data) or jumps > 16:
                raise ValueError("puntatore DNS non valido")
            if end_offset is None:
                end_offset = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), end_offset if end_offset is not None else offset


def _build_ptr_query(ip: str, query_id: int = 0) -> bytes:
    rev_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    query = struct.pack("!HHHHHH", query_id, 0, 1, 0, 0, 0)
    for label in rev_ip.split("."):
        query += bytes([len(label)]) + label.encode("ascii")
    return query + b"\x00" + struct.pack("!HH", 12, 1)  # fine nome, tipo PTR, classe IN


def _parse_ptr_response(data: bytes) -> str:
    """Restituisce il primo record PTR della sezione risposte, saltando la domanda ripetuta."""
    if len(data) < 12:
        return ""
    _qid, _flags, qdcount, ancount, _ns, _ar = struct.unpack_from("!HHHHHH", data, 0)
    offset = 12
    for _ in range(qdcount):
        _, offset = _dns_read_name(data, offset)
        offset += 4
    for _ in range(ancount):
        _, offset = _dns_read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if rtype == 12:
            name, _ = _dns_read_name(data, offset)
            return name.rstrip(".")
        offset += rdlength
    return ""


def _resolve_mdns_name(ip: str, timeout: float = 0.4) -> str:
    """Chiede il nome .local al dispositivo con una query mDNS unicast (UDP 5353, RFC 6762 §6.7)."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(_build_ptr_query(ip, query_id=0x4C53), (ip, 5353))
            data, _ = sock.recvfrom(4096)
        return _parse_ptr_response(data)
    except (OSError, ValueError, struct.error):
        return ""


def _parse_ssdp_response(text: str) -> str:
    headers: Dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            headers.setdefault(key.strip().lower(), value.strip())
    if headers.get("server"):
        return headers["server"]
    if headers.get("location"):
        return f"UPnP ({headers['location']})"
    return ""


def _probe_ssdp_info(ip: str, timeout: float = 0.5) -> str:
    """Sonda l'header SSDP UPnP (UDP 1900)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            req = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {ip}:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 1\r\n"
                "ST: ssdp:all\r\n\r\n"
            ).encode("utf-8")
            sock.sendto(req, (ip, 1900))
            data, _ = sock.recvfrom(2048)
        return _parse_ssdp_response(data.decode("utf-8", errors="ignore"))
    except OSError:
        return ""


def _nbtstat(ip: str) -> str:
    try:
        return _run_console(["nbtstat", "-A", ip], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return "(nbtstat non disponibile o timeout)"


def _parse_ports(txt: str, max_ports: int = 1024) -> List[Tuple[int, str]]:
    """Interpreta '22, 80, 8000-8010'. Ignora porte fuori da 1-65535 e duplicati."""
    seen: Dict[int, str] = {}
    for part in txt.split(","):
        part = part.strip()
        if "-" in part:
            try:
                s_p, e_p = sorted(map(int, part.split("-", 1)))
            except ValueError:
                continue
            for p in range(max(1, s_p), min(e_p, 65535) + 1):
                seen.setdefault(p, f"Porta {p}")
        elif part.isdigit() and 1 <= int(part) <= 65535:
            seen.setdefault(int(part), f"Porta {int(part)}")
    return list(seen.items())[:max_ports]


def _probe_port(ip: str, port: int, timeout: float) -> Optional[str]:
    """None se chiusa, altrimenti la prima riga del banner ('' se il servizio non ne invia)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) != 0:
                return None
        except OSError:
            return None
        try:
            if port in (80, 8080, 5000, 8000, 8008, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = s.recv(256)
            first = data.decode("utf-8", errors="replace").splitlines()
            return first[0].strip()[:80] if first else ""
        except OSError:
            return ""


def _probe_ports_with_banner(
    ip: str,
    ports: List[Tuple[int, str]],
    timeout: float = 0.5,
    cancel: Optional[threading.Event] = None,
) -> List[Tuple[int, str, str]]:
    """Sonda in parallelo una lista di porte TCP con estrazione del banner di risposta."""
    results: List[Tuple[int, str, str]] = []
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(64, max(1, len(ports))))
    try:
        futs = {ex.submit(_probe_port, ip, port, timeout): (port, label) for port, label in ports}
        for fu in concurrent.futures.as_completed(futs):
            if cancel is not None and cancel.is_set():
                break
            banner = fu.result()
            if banner is not None:
                port, label = futs[fu]
                results.append((port, label, banner))
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return sorted(results)


# --- AGGIORNAMENTO AUTOMATICO ---

UPDATE_ASSET_NAME = "LanScanner.exe"


def _pick_update_asset(release: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Dati del file LanScanner.exe di una release GitHub: url, dimensione e SHA-256 dichiarato."""
    for asset in release.get("assets") or []:
        if asset.get("name") == UPDATE_ASSET_NAME and asset.get("browser_download_url"):
            digest = str(asset.get("digest") or "")
            return {
                "url": asset["browser_download_url"],
                "size": int(asset.get("size") or 0),
                "sha256": digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else "",
            }
    return None


def _can_self_update() -> bool:
    """Solo l'exe compilato può sostituirsi; da sorgente si apre la pagina della release."""
    return sys.platform == "win32" and bool(getattr(sys, "frozen", False))


def _current_exe() -> pathlib.Path:
    return pathlib.Path(sys.executable).resolve()


def _download_update(
    asset: Dict[str, Any],
    dest: pathlib.Path,
    progress=None,
    cancel: Optional[threading.Event] = None,
) -> pathlib.Path:
    """Scarica il nuovo exe accanto a quello attuale e lo verifica (dimensione, SHA-256, intestazione MZ)."""
    part = dest.with_name(dest.name + ".part")
    expected_size = int(asset.get("size") or 0)
    h = hashlib.sha256()
    done = 0
    req = urllib.request.Request(asset["url"], headers={"User-Agent": "LanScanner-Updater"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp, open(part, "wb") as fp:
            total = expected_size or int(resp.headers.get("Content-Length") or 0)
            while True:
                if cancel is not None and cancel.is_set():
                    raise RuntimeError("download annullato")
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                fp.write(chunk)
                h.update(chunk)
                done += len(chunk)
                if progress is not None:
                    progress(done, total)
        if expected_size and done != expected_size:
            raise RuntimeError(f"file incompleto ({done} di {expected_size} byte)")
        if asset.get("sha256") and h.hexdigest().lower() != asset["sha256"]:
            raise RuntimeError("checksum SHA-256 non corrispondente: file scartato")
        with open(part, "rb") as fp:
            if fp.read(2) != b"MZ":
                raise RuntimeError("il file scaricato non è un eseguibile Windows")
        os.replace(part, dest)
        return dest
    except BaseException:
        try:
            part.unlink()
        except OSError:
            pass
        raise


def _install_update(new_exe: pathlib.Path, current_exe: pathlib.Path) -> pathlib.Path:
    """Mette il nuovo exe al posto di quello in uso.

    Windows non permette di sovrascrivere un exe in esecuzione ma permette di rinominarlo:
    l'attuale diventa .old (cancellato al prossimo avvio) e il nuovo prende il suo nome.
    """
    old = current_exe.with_name(current_exe.name + ".old")
    if old.exists():
        old.unlink()
    os.replace(current_exe, old)
    try:
        os.replace(new_exe, current_exe)
    except OSError:
        os.replace(old, current_exe)
        raise
    return old


def _launch_detached(exe: pathlib.Path) -> None:
    env = dict(os.environ)
    # Senza questa variabile il nuovo exe PyInstaller riuserebbe la cartella temporanea di questo processo
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen([str(exe)], cwd=str(exe.parent), env=env, creationflags=flags, close_fds=True)


def _cleanup_previous_update() -> None:
    """Cancella il .old e i download rimasti dall'aggiornamento precedente (se non più in uso)."""
    if not _can_self_update():
        return
    exe = _current_exe()
    for leftover in (exe.name + ".old", exe.name + ".download", exe.name + ".download.part"):
        try:
            exe.with_name(leftover).unlink()
        except OSError:
            pass


class UpdateDownloadThread(QThread):
    progress = Signal(int, int)
    downloaded = Signal(str)
    failed = Signal(str)

    def __init__(self, asset: Dict[str, Any], dest: pathlib.Path, parent=None):
        super().__init__(parent)
        self.asset = asset
        self.dest = dest
        self.cancel = threading.Event()

    def run(self) -> None:
        try:
            path = _download_update(self.asset, self.dest, self.progress.emit, self.cancel)
        except Exception as e:
            self.failed.emit(str(e))
            return
        self.downloaded.emit(str(path))


# --- BACKGROUND THREADS ---

class UpdateCheckerThread(QThread):
    update_found = Signal(str, str, str, object)  # tag, pagina release, note, asset exe (o None)
    no_update_found = Signal(str)
    check_failed = Signal(str)

    def __init__(self, current_version: str = APP_VERSION, parent=None):
        super().__init__(parent)
        self.current_version = current_version

    def run(self) -> None:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        headers = {
            "User-Agent": "LanScanner-Updater",
            "Accept": "application/vnd.github.v3+json",
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=6) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    tag_name = data.get("tag_name", "").strip()
                    latest_ver = tag_name.lstrip("v")
                    html_url = data.get("html_url", f"https://github.com/{GITHUB_REPO}/releases")
                    notes = data.get("body", "")

                    if self._is_newer(latest_ver, self.current_version):
                        self.update_found.emit(tag_name, html_url, notes, _pick_update_asset(data))
                    else:
                        self.no_update_found.emit(self.current_version)
                    return
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.no_update_found.emit(self.current_version)
                return
            self.check_failed.emit(f"HTTP Error {e.code}")
            return
        except Exception as ex:
            self.check_failed.emit(str(ex))
            return

    @staticmethod
    def _is_newer(latest_str: str, current_str: str) -> bool:
        def parse_version(v: str) -> List[int]:
            parts = re.findall(r"\d+", v)
            return [int(p) for p in parts] if parts else [0]

        return parse_version(latest_str) > parse_version(current_str)


_ALIVE_THREADS: "set[QThread]" = set()


def _keep_alive(thread: QThread) -> None:
    """Riferimento forte finché il thread lavora, anche se la finestra che l'ha lanciato è già chiusa.

    Va usato con thread senza parent: un QThread distrutto mentre gira fa terminare l'app.
    """
    _ALIVE_THREADS.add(thread)
    thread.finished.connect(lambda: _ALIVE_THREADS.discard(thread))


class TaskThread(QThread):
    """Esegue fn() fuori dal thread della GUI e consegna il risultato con un segnale.

    Gli aggiornamenti della GUI da un threading.Thread con QTimer.singleShot non partono
    mai (quel thread non ha un event loop Qt): i segnali Qt invece arrivano in coda al thread principale.
    """

    result_ready = Signal(object)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn
        _keep_alive(self)

    def run(self) -> None:
        try:
            res = self._fn()
        except Exception as e:  # il chiamante mostra l'errore come testo
            res = e
        self.result_ready.emit(res)


class ContinuousPingWorker(QThread):
    ping_result = Signal(bool, float, str)

    def __init__(self, ip: str, interval_sec: float = 1.0, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.interval_sec = interval_sec
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            ok, rtt = _ping_one(self.ip, timeout_ms=800)
            if self._stop_event.is_set():
                break
            now_str = time.strftime("%H:%M:%S")
            self.ping_result.emit(ok, rtt, now_str)
            self._stop_event.wait(self.interval_sec)


_TRACERT_HOP_RE = re.compile(r"^\s*(\d+)\s+((?:(?:<?\d+\s*ms|\*)\s+){1,3})(\d{1,3}(?:\.\d{1,3}){3})")


def _parse_tracert_line(line: str) -> Optional[Tuple[int, str, float]]:
    """Riconosce una riga di tracert -d: (hop, ip, media RTT in ms) oppure None."""
    m = _TRACERT_HOP_RE.search(line)
    if not m:
        return None
    rtts = [float(x) for x in re.findall(r"<?(\d+)\s*ms", m.group(2))]
    avg_rtt = round(sum(rtts) / len(rtts), 1) if rtts else 0.0
    return int(m.group(1)), m.group(3), avg_rtt


class TracerouteWorker(QThread):
    hop_found = Signal(int, str, float, str)
    trace_finished = Signal()

    def __init__(self, target_ip: str, max_hops: int = 30, parent=None):
        super().__init__(parent)
        self.target_ip = target_ip
        self.max_hops = max_hops
        self._running = True
        self._proc: Optional[subprocess.Popen] = None

    def stop(self) -> None:
        self._running = False
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass

    def run(self) -> None:
        try:
            cr = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            self._proc = subprocess.Popen(
                ["tracert", "-d", "-h", str(self.max_hops), "-w", "750", self.target_ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding=_console_encoding(),
                errors="replace",
                creationflags=cr,
            )
            for line in iter(self._proc.stdout.readline, ""):
                if not self._running:
                    break
                hop = _parse_tracert_line(line)
                if hop:
                    hop_n, ip, avg_rtt = hop
                    self.hop_found.emit(hop_n, ip, avg_rtt, _resolve_hostname(ip))
                    if ip == self.target_ip:
                        break
        except Exception:
            pass
        finally:
            self.stop()
        self.trace_finished.emit()


class ScanWorkerThread(QThread):
    progress_updated = Signal(int, int)
    initial_alive_found = Signal(list)
    hostname_resolved = Signal(str, str, str, str)  # ip, hostname, hint, note
    names_progress = Signal(int, int)
    scan_finished = Signal(int)
    scan_interrupted = Signal()
    scan_error = Signal(str)

    def __init__(self, hosts: List[str], device_notes: Dict[str, str], max_workers: int = 64, parent=None):
        super().__init__(parent)
        self.hosts = hosts
        self.device_notes = dict(device_notes)
        self.max_workers = max_workers
        self._cancel_event = threading.Event()

    def stop(self) -> None:
        self._cancel_event.set()

    def _parallel(self, fn, items: List[str], workers: int):
        """Esegue fn(item) in parallelo e restituisce (item, risultato) man mano; si ferma subito su stop()."""
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        try:
            futs = {ex.submit(fn, it): it for it in items}
            for fu in concurrent.futures.as_completed(futs):
                if self._cancel_event.is_set():
                    return
                try:
                    res = fu.result()
                except Exception:
                    res = None
                yield futs[fu], res
        finally:
            # Senza cancel_futures l'uscita aspetterebbe tutti i ping ancora in coda (fino a ~50 s)
            ex.shutdown(wait=False, cancel_futures=True)

    @staticmethod
    def _identify(ip: str) -> Tuple[str, str, str]:
        hn = _resolve_hostname(ip) or ""
        mdns_name = _resolve_mdns_name(ip) if not hn else ""
        ssdp_info = _probe_ssdp_info(ip) if not hn and not mdns_name else ""
        return hn, mdns_name, ssdp_info

    def run(self) -> None:
        timeout_ms = 750
        ping_results: Dict[str, Tuple[bool, float]] = {}
        total = len(self.hosts)

        try:
            _load_oui_map()
            initial_arp = _arp_map()

            # Scansione ICMP Ping nativa parallela
            for done, (ip, res) in enumerate(
                self._parallel(lambda h: _ping_one(h, timeout_ms), self.hosts, self.max_workers), 1
            ):
                ping_results[ip] = res or (False, 0.0)
                if done % 8 == 0 or done == total:
                    self.progress_updated.emit(done, total)

            if self._cancel_event.is_set():
                self.scan_interrupted.emit()
                return

            time.sleep(0.2)
            combined_arp = {**initial_arp, **_arp_map()}

            # Stesso MAC su più IP che rispondono al ping: possibile conflitto, proxy ARP o più indirizzi.
            # Un IP solo in cache ARP con il MAC di un host attivo è quasi sempre il suo indirizzo DHCP precedente.
            alive_by_mac: Dict[str, List[str]] = {}
            for ip_s, m in combined_arp.items():
                if ping_results.get(ip_s, (False, 0.0))[0]:
                    alive_by_mac.setdefault(m, []).append(ip_s)
            mac_counts = {m: len(ips) for m, ips in alive_by_mac.items()}

            rows: List[Tuple[str, str, str, str, str, str, str]] = []
            for ip in self.hosts:
                ok, rtt = ping_results.get(ip, (False, 0.0))
                mac = combined_arp.get(ip, "")
                note = self.device_notes.get(mac, self.device_notes.get(ip, ""))
                v = _vendor_from_mac(mac) if mac else ""

                if ok:
                    status_str = f"🟢 Attivo ({int(rtt)} ms)" if rtt > 0 else "🟢 Attivo (<1 ms)"
                elif mac:
                    # Nella cache ARP ma senza risposta al ping: firewall oppure voce recente di un dispositivo spento
                    status_str = "🟡 Solo ARP (no ping)"
                else:
                    continue
                rows.append((ip, status_str, mac or "—", v or "—", "...", "—", note or "—"))

            sorted_rows = sorted(rows, key=lambda x: int(ipaddress.IPv4Address(x[0])))
            self.initial_alive_found.emit(sorted_rows)

            # Risoluzione Hostname, mDNS, SSDP ed Hint in parallelo: un host senza nome DNS costa ~6 s
            sorted_ips = [r[0] for r in sorted_rows]
            for done, (ip, res) in enumerate(self._parallel(self._identify, sorted_ips, 32), 1):
                hn, mdns_name, ssdp_info = res or ("", "", "")
                mac = combined_arp.get(ip, "")
                v = _vendor_from_mac(mac) if mac else ""
                disp_hn = hn or mdns_name or "—"
                alive_ok = ping_results.get(ip, (False, 0.0))[0]
                current_ips = [] if alive_ok else alive_by_mac.get(mac, [])
                hint = _quick_hint(
                    disp_hn, v, mac, mdns_name, ssdp_info,
                    mac_counts.get(mac, 0) if alive_ok else 0,
                    previous_ip_of=current_ips[0] if current_ips else "",
                )
                note = self.device_notes.get(mac, self.device_notes.get(ip, "")) or "—"
                self.hostname_resolved.emit(ip, disp_hn, hint, note)
                self.names_progress.emit(done, len(sorted_ips))

            if self._cancel_event.is_set():
                self.scan_interrupted.emit()
                return

            self.scan_finished.emit(len(sorted_rows))

        except Exception as e:
            self.scan_error.emit(str(e))


# --- DIALOGS & TOOLS ---

def _exec_dialog(dlg: QDialog) -> int:
    """Apre la finestra modale e la distrugge alla chiusura (con parent resterebbe in memoria fino all'uscita)."""
    try:
        return dlg.exec()
    finally:
        dlg.deleteLater()


class SubnetCalculatorDialog(QDialog):
    """Calcolatore Subnet / Notazione CIDR e suddivisione IP."""

    def __init__(self, cidr_or_ip: str = "192.168.1.0/24", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Calcolatore Subnet & Notazione CIDR")
        self.setFixedSize(500, 360)
        _set_window_icon(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        lbl_hdr = QLabel("🌐 Analisi Subnet IPv4")
        lbl_hdr.setFont(QFont("Segoe UI", 13, QFont.Bold))
        layout.addWidget(lbl_hdr)

        form_lay = QHBoxLayout()
        self.txt_cidr = QLineEdit(cidr_or_ip)
        self.txt_cidr.setFont(QFont("Consolas", 10, QFont.Bold))
        btn_calc = QPushButton("⚡ Calcola")
        btn_calc.setObjectName("PrimaryBtn")
        btn_calc.setCursor(Qt.PointingHandCursor)
        btn_calc.clicked.connect(self._calculate)

        form_lay.addWidget(QLabel("Indirizzo CIDR:"))
        form_lay.addWidget(self.txt_cidr)
        form_lay.addWidget(btn_calc)
        layout.addLayout(form_lay)

        self.txt_info = QTextEdit()
        self.txt_info.setReadOnly(True)
        self.txt_info.setFont(QFont("Consolas", 9.5))
        layout.addWidget(self.txt_info)

        btn_close = QPushButton("Chiudi")
        btn_close.setObjectName("SecondaryBtn")
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignRight)

        self._calculate()

    def _calculate(self) -> None:
        raw = self.txt_cidr.text().strip()
        try:
            if "/" not in raw:
                raw += "/24"
            net = ipaddress.IPv4Network(raw, strict=False)
            hosts = list(net.hosts())
            first_host = str(hosts[0]) if hosts else "N/A"
            last_host = str(hosts[-1]) if hosts else "N/A"

            info = [
                f"Rete CIDR:           {net.with_prefixlen}",
                f"Maschera Subnet:     {net.netmask}",
                f"Indirizzo Rete:      {net.network_address}",
                f"Indirizzo Broadcast: {net.broadcast_address}",
                f"Host Utili Totali:   {net.num_addresses - 2 if net.prefixlen <= 30 else net.num_addresses}",
                f"Primo Host Utile:    {first_host}",
                f"Ultimo Host Utile:   {last_host}",
                f"Tipo Indirizzo:      {'Privato (LAN)' if net.is_private else 'Pubblico (WAN)'}",
            ]
            self.txt_info.setText("\n".join(info))
        except Exception as e:
            self.txt_info.setText(f"Errore calcolo subnet: {e}")


class CustomPortScanDialog(QDialog):
    """Scansione porte TCP avanzata e personalizzabile con Banner Grabbing."""

    PORTS_DEFAULT = [
        (80, "HTTP Web Server"),
        (443, "HTTPS Sec Web"),
        (445, "SMB File Share"),
        (22, "SSH Terminal"),
        (21, "FTP Transfer"),
        (23, "Telnet Remote"),
        (53, "DNS Service"),
        (3389, "RDP Remote Desktop"),
        (5900, "VNC Remote Desktop"),
        (8080, "HTTP Alt Proxy"),
        (8443, "HTTPS Alt"),
        (5000, "UPnP / Synology"),
        (9100, "JetDirect Print"),
    ]

    def __init__(self, target_ip: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Scansione Porte Personalizzata — {target_ip}")
        self.resize(600, 450)
        _set_window_icon(self)
        self.target_ip = target_ip

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        hdr_box = QHBoxLayout()
        lbl_target = QLabel(f"🎯 Target: <b>{target_ip}</b>")
        lbl_target.setFont(QFont("Segoe UI", 11))
        hdr_box.addWidget(lbl_target)

        self.txt_ports = QLineEdit("80, 443, 445, 22, 21, 23, 53, 3389, 5900, 8080, 8443, 5000, 9100")
        self.txt_ports.setFont(QFont("Consolas", 9.5))
        hdr_box.addWidget(QLabel("Porte da testare:"))
        hdr_box.addWidget(self.txt_ports)

        btn_scan = QPushButton("🔍 Avvia Scan")
        btn_scan.setObjectName("PrimaryBtn")
        btn_scan.setCursor(Qt.PointingHandCursor)
        btn_scan.clicked.connect(self._run_scan)
        hdr_box.addWidget(btn_scan)

        layout.addLayout(hdr_box)

        self.txt_results = QTextEdit()
        self.txt_results.setReadOnly(True)
        self.txt_results.setFont(QFont("Consolas", 9.5))
        layout.addWidget(self.txt_results)

        btn_box = QHBoxLayout()
        btn_copy = QPushButton("📋 Copia Risultati")
        btn_copy.setObjectName("SecondaryBtn")
        btn_copy.setCursor(Qt.PointingHandCursor)
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self.txt_results.toPlainText()))

        btn_close = QPushButton("Chiudi")
        btn_close.setObjectName("SecondaryBtn")
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.accept)

        btn_box.addWidget(btn_copy)
        btn_box.addStretch()
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)

        self._cancel = threading.Event()
        self._task: Optional[TaskThread] = None
        self.btn_scan = btn_scan
        self.txt_ports.returnPressed.connect(self._run_scan)
        self._run_scan()

    MAX_PORTS = 1024

    def _run_scan(self) -> None:
        if self._task is not None and self._task.isRunning():
            return
        ports_to_scan = _parse_ports(self.txt_ports.text(), self.MAX_PORTS) or self.PORTS_DEFAULT
        labels = dict(self.PORTS_DEFAULT)
        ports_to_scan = [(p, labels.get(p, lbl)) for p, lbl in ports_to_scan]
        self.txt_results.setText(f"Scansione di {len(ports_to_scan)} porte e lettura banner in corso...")
        self.btn_scan.setEnabled(False)

        ip, cancel = self.target_ip, self._cancel

        def job() -> str:
            open_found = _probe_ports_with_banner(ip, ports_to_scan, cancel=cancel)
            lines = [f"=== SCANSIONE PORTE TCP SU {ip} ({len(ports_to_scan)} porte) ===\n\n"]
            if open_found:
                for port, label, banner in open_found:
                    b_str = f" → Banner: [{banner}]" if banner else ""
                    lines.append(f"🟢 Porta {port:<5} OPEN ({label}){b_str}\n")
            else:
                lines.append("❌ Nessuna porta aperta tra quelle testate.\n")
            return "".join(lines)

        self._task = TaskThread(job)
        self._task.result_ready.connect(self._on_scan_done)
        self._task.start()

    @Slot(object)
    def _on_scan_done(self, report: object) -> None:
        self.txt_results.setText(str(report) if not isinstance(report, Exception) else f"Errore: {report}")
        self.btn_scan.setEnabled(True)

    def done(self, result: int) -> None:
        self._cancel.set()
        super().done(result)


class TracerouteDialog(QDialog):
    """Traceroute grafico con avanzamento hop-by-hop."""

    def __init__(self, target_ip: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Traceroute — Rotta verso {target_ip}")
        self.resize(580, 420)
        _set_window_icon(self)
        self.target_ip = target_ip

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        layout.addWidget(QLabel(f"🛤️ Analisi percorso di rete (IP Hop) verso <b>{target_ip}</b>:"))

        self.table = QTreeWidget()
        self.table.setHeaderLabels(["Hop #", "Indirizzo IP", "Latenza RTT", "Hostname / Nodo"])
        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 110)
        self.table.header().setStretchLastSection(True)
        layout.addWidget(self.table)

        btn_box = QHBoxLayout()
        self.btn_toggle = QPushButton("🛑 Interrompi")
        self.btn_toggle.setObjectName("SecondaryBtn")
        self.btn_toggle.setCursor(Qt.PointingHandCursor)
        self.btn_toggle.clicked.connect(self._stop_trace)

        btn_close = QPushButton("Chiudi")
        btn_close.setObjectName("PrimaryBtn")
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.accept)

        btn_box.addWidget(self.btn_toggle)
        btn_box.addStretch()
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)

        self.worker = TracerouteWorker(target_ip)
        _keep_alive(self.worker)
        self.worker.hop_found.connect(self._on_hop_found)
        self.worker.trace_finished.connect(self._on_finished)
        self.worker.start()

    def done(self, result: int) -> None:
        # Termina tracert; il thread finisce da solo anche se la finestra viene distrutta
        self.worker.stop()
        super().done(result)

    def _on_hop_found(self, hop: int, ip: str, rtt: float, hostname: str) -> None:
        rtt_str = f"{rtt:.1f} ms" if rtt > 0 else "<1 ms"
        item = QTreeWidgetItem(self.table, [str(hop), ip, rtt_str, hostname or "—"])
        item.setTextAlignment(0, Qt.AlignCenter)

    def _on_finished(self) -> None:
        self.btn_toggle.setEnabled(False)
        if self.btn_toggle.text() != "Interrotto":
            self.btn_toggle.setText("Completato")

    def _stop_trace(self) -> None:
        if self.worker.isRunning():
            self.btn_toggle.setText("Interrotto")
            self.worker.stop()


class ContinuousPingDialog(QDialog):
    """Finestra di monitoraggio continuo latenza Ping RTT per un dispositivo."""

    def __init__(self, target_ip: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Ping Continuo — {target_ip}")
        self.resize(560, 420)
        _set_window_icon(self)
        self.target_ip = target_ip

        self.sent_count = 0
        self.recv_count = 0
        self.rtt_list: List[float] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        hdr_frame = QHBoxLayout()
        hdr_frame.setSpacing(10)

        self.card_sent = QLabel("Inviati: <b>0</b>")
        self.card_recv = QLabel("Ricevuti: <b>0</b>")
        self.card_loss = QLabel("Persi: <b>0%</b>")
        self.card_rtt = QLabel("Latenza Media: <b>- ms</b>")

        for card in (self.card_sent, self.card_recv, self.card_loss, self.card_rtt):
            card.setObjectName("InfoCard")
            card.setAlignment(Qt.AlignCenter)
            card.setFixedHeight(38)
            hdr_frame.addWidget(card)

        layout.addLayout(hdr_frame)

        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(QFont("Consolas", 9.5))
        layout.addWidget(self.txt_log)

        btn_box = QHBoxLayout()
        self.btn_toggle = QPushButton("⏸️ Pausa")
        self.btn_toggle.setObjectName("SecondaryBtn")
        self.btn_toggle.setCursor(Qt.PointingHandCursor)
        self.btn_toggle.clicked.connect(self._toggle_ping)

        btn_copy = QPushButton("📋 Copia Log")
        btn_copy.setObjectName("SecondaryBtn")
        btn_copy.setCursor(Qt.PointingHandCursor)
        btn_copy.clicked.connect(self._copy_log)

        btn_close = QPushButton("Chiudi")
        btn_close.setObjectName("PrimaryBtn")
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.accept)

        btn_box.addWidget(self.btn_toggle)
        btn_box.addWidget(btn_copy)
        btn_box.addStretch()
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)

        self._start_worker()

    def _on_ping_result(self, ok: bool, rtt: float, now_str: str) -> None:
        self.sent_count += 1
        if ok:
            self.recv_count += 1
            self.rtt_list.append(rtt)
            rtt_str = f"{int(rtt)} ms" if rtt > 0 else "<1 ms"
            self.txt_log.append(f"[{now_str}] Risposta da {self.target_ip}: tempo={rtt_str}")
        else:
            self.txt_log.append(f"[{now_str}] Richiesta scaduta per {self.target_ip} (Timeout)")

        loss_pct = round(((self.sent_count - self.recv_count) / self.sent_count) * 100, 1)
        avg_rtt = round(sum(self.rtt_list) / len(self.rtt_list), 1) if self.rtt_list else 0.0

        self.card_sent.setText(f"Inviati: <b>{self.sent_count}</b>")
        self.card_recv.setText(f"Ricevuti: <b>{self.recv_count}</b>")
        self.card_loss.setText(f"Persi: <b>{loss_pct}%</b>")
        self.card_rtt.setText(f"Latenza Media: <b>{avg_rtt} ms</b>" if self.rtt_list else "Latenza: -")

    def _start_worker(self) -> None:
        self.worker = ContinuousPingWorker(self.target_ip, interval_sec=1.0)
        _keep_alive(self.worker)
        self.worker.ping_result.connect(self._on_ping_result)
        self.worker.start()

    def _stop_worker(self) -> None:
        # Scollegato subito: l'ultimo ping in volo non deve arrivare dopo la pausa
        self.worker.stop()
        try:
            self.worker.ping_result.disconnect(self._on_ping_result)
        except (RuntimeError, TypeError):
            pass

    def _toggle_ping(self) -> None:
        if not self.worker._stop_event.is_set():
            self._stop_worker()
            self.btn_toggle.setText("▶️ Riprendi")
        else:
            self._start_worker()
            self.btn_toggle.setText("⏸️ Pausa")

    def _copy_log(self) -> None:
        QApplication.clipboard().setText(self.txt_log.toPlainText())
        QMessageBox.information(self, "Copia", "Log dei ping copiato negli appunti.")

    def done(self, result: int) -> None:
        # "Chiudi" (accept), Esc e la X passano tutti da qui; closeEvent copriva solo la X
        self._stop_worker()
        super().done(result)


class DeviceDetailDialog(QDialog):
    PORTS = CustomPortScanDialog.PORTS_DEFAULT

    def __init__(self, ip: str, row_values: Tuple[str, ...], parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Dettaglio Dispositivo — {ip}")
        self.resize(660, 520)
        _set_window_icon(self)
        self._ip = ip
        self._row = row_values

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(4)

        def add_info(lbl_text, val_text, row, col):
            l = QLabel(f"<b>{lbl_text}:</b>")
            v = QLabel(str(val_text or "—"))
            # Hostname e banner arrivano dalla rete: niente interpretazione come rich text
            v.setTextFormat(Qt.PlainText)
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(l, row, col * 2)
            grid.addWidget(v, row, col * 2 + 1)

        add_info("Indirizzo IP", row_values[0] if len(row_values) > 0 else ip, 0, 0)
        add_info("Stato Ping", row_values[1] if len(row_values) > 1 else "-", 0, 1)
        add_info("Indirizzo MAC", row_values[2] if len(row_values) > 2 else "-", 1, 0)
        add_info("Vendor OUI", row_values[3] if len(row_values) > 3 else "-", 1, 1)
        add_info("Hostname", row_values[4] if len(row_values) > 4 else "-", 2, 0)
        add_info("Indizio / Tipo", row_values[5] if len(row_values) > 5 else "-", 2, 1)
        if len(row_values) > 6:
            add_info("Note Utente", row_values[6], 3, 0)

        layout.addLayout(grid)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setObjectName("HorizontalSeparator")
        layout.addWidget(sep)

        lbl_report = QLabel("📜 Report di Analisi Avanzata (mDNS + SSDP + NetBIOS + Porte TCP):")
        lbl_report.setFont(QFont("Segoe UI", 10, QFont.Bold))
        layout.addWidget(lbl_report)

        self.txt_report = QTextEdit()
        self.txt_report.setReadOnly(True)
        self.txt_report.setFont(QFont("Consolas", 9.5))
        layout.addWidget(self.txt_report)

        btn_box = QHBoxLayout()
        self._task: Optional[TaskThread] = None
        btn_analyze = QPushButton("🔍 Analizza Dettagliatamente")
        btn_analyze.setObjectName("PrimaryBtn")
        btn_analyze.setCursor(Qt.PointingHandCursor)
        btn_analyze.clicked.connect(self._start_analysis)
        self.btn_analyze = btn_analyze

        btn_copy = QPushButton("📋 Copia Report")
        btn_copy.setObjectName("SecondaryBtn")
        btn_copy.setCursor(Qt.PointingHandCursor)
        btn_copy.clicked.connect(self._copy_report)

        btn_close = QPushButton("Chiudi")
        btn_close.setObjectName("SecondaryBtn")
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.accept)

        btn_box.addWidget(btn_analyze)
        btn_box.addWidget(btn_copy)
        btn_box.addStretch()
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)

        self.txt_report.setText("Clicca su 'Analizza Dettagliatamente' per eseguire il sondaggio avanzato dei protocolli di rete.")

    def _start_analysis(self) -> None:
        if self._task is not None and self._task.isRunning():
            return
        self.txt_report.setText("Analisi avanzata in corso (mDNS + UPnP + NetBIOS + Porte)...\nAttendere qualche secondo...")
        self.btn_analyze.setEnabled(False)
        ip, ports = self._ip, self.PORTS

        def job() -> str:
            # Le sonde sono indipendenti: in parallelo il report arriva nel tempo della più lenta
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
                f_hn = ex.submit(_resolve_hostname, ip)
                f_mdns = ex.submit(_resolve_mdns_name, ip)
                f_ssdp = ex.submit(_probe_ssdp_info, ip)
                f_nbt = ex.submit(_nbtstat, ip)
                f_ports = ex.submit(_probe_ports_with_banner, ip, ports)
            lines = [f"=== REPORT DETTAGLIATO DISPOSITIVO {ip} ===\n\n"]
            lines.append(f"Hostname (DNS Reverse): {f_hn.result() or '—'}\n")
            lines.append(f"Hostname mDNS (.local):  {f_mdns.result() or '—'}\n")
            lines.append(f"UPnP / SSDP Server:     {f_ssdp.result() or '—'}\n\n")

            lines.append("=== NetBIOS Name Service (nbtstat -A) ===\n")
            lines.append(f_nbt.result().strip() + "\n\n")

            lines.append("=== Sondaggio Porte TCP Comuni con Banner ===\n")
            openp = f_ports.result()
            if openp:
                for p, lbl, b in openp:
                    b_str = f" [{b}]" if b else ""
                    lines.append(f"• Porta {p} ({lbl}){b_str}\n")
            else:
                lines.append("Nessuna delle porte standard testate risponde in apertura.\n")

            lines.append("\n=== Note ===\n")
            lines.append("Produttore hardware derivato dal database IEEE OUI. Eventuali firewall locali o di rete possono filtrare i pacchetti.\n")
            return "".join(lines)

        self._task = TaskThread(job)
        self._task.result_ready.connect(self._on_analysis_done)
        self._task.start()

    @Slot(object)
    def _on_analysis_done(self, report: object) -> None:
        self.txt_report.setText(str(report) if not isinstance(report, Exception) else f"Errore durante l'analisi: {report}")
        self.btn_analyze.setEnabled(True)

    def _copy_report(self) -> None:
        QApplication.clipboard().setText(self.txt_report.toPlainText())
        QMessageBox.information(self, "Copia", "Report di dettaglio copiato negli appunti.")


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Informazioni su {APP_NAME}")
        self.setFixedSize(520, 440)
        _set_window_icon(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        hdr_frame = QHBoxLayout()
        hdr_frame.setSpacing(14)

        lbl_logo = QLabel("📡")
        lbl_logo.setFont(QFont("Segoe UI Emoji", 26))

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        lbl_title = QLabel(APP_NAME)
        lbl_title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        lbl_ver = QLabel(f"Versione {APP_VERSION} (Material 3 Edition)")
        lbl_ver.setFont(QFont("Segoe UI", 10))

        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_ver)
        hdr_frame.addWidget(lbl_logo)
        hdr_frame.addLayout(title_box)
        hdr_frame.addStretch()

        layout.addLayout(hdr_frame)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setObjectName("HorizontalSeparator")
        layout.addWidget(sep)

        body_text = (
            f"<b>Azienda:</b> {APP_COMPANY}<br>"
            f"<b>Sviluppatore:</b> {APP_DEVELOPER}<br>"
            f"<b>Sito Web:</b> <a href='{WEBSITE_URL}'>{WEBSITE_URL}</a><br>"
            f"<b>Repository:</b> <a href='https://github.com/{GITHUB_REPO}'>GitHub Repository</a><br><br>"
            "<b>Novità Versione 1.3.0:</b><br>"
            "• Ping ICMP nativo ad alta velocità via Windows API (ctypes)<br>"
            "• Notazione CIDR e Calcolatore Subnet incorporato<br>"
            "• Discovery mDNS (.local) ed UPnP / SSDP per dispositivi IoT/Smart TV<br>"
            "• Custom Port Scanner con estrazione dei banner TCP<br>"
            "• Rilevatore rotta Traceroute graficamente integrato<br>"
            "• Assegnazione Note Utente e salvataggio locale<br>"
            "• Esportazione multi-formato in CSV, JSON ed HTML Interattivo<br><br>"
            "<small><i>Database IEEE OUI derivato dal progetto Wireshark.</i></small>"
        )

        lbl_body = QLabel(body_text)
        lbl_body.setWordWrap(True)
        lbl_body.setOpenExternalLinks(True)
        lbl_body.setFont(QFont("Segoe UI", 9.5))
        layout.addWidget(lbl_body)

        layout.addStretch()

        btn_close = QPushButton("Chiudi")
        btn_close.setObjectName("PrimaryBtn")
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignRight)


class LegalDisclaimerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Avviso di Responsabilità & Conformità")
        self.setFixedSize(480, 320)
        _set_window_icon(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        lbl_title = QLabel("⚖️ Avviso Legale e Condizioni d'Uso")
        lbl_title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(lbl_title)

        disc = (
            "<b>1. Autorizzazione di Rete:</b><br>"
            "L'uso di strumenti di scansione di rete deve avvenire in conformità con "
            "le leggi locali sulla sicurezza informatica e la privacy. Scansionare reti senza "
            "l'esplicito consenso del proprietario o dell'amministratore può costituire illecito.<br><br>"
            "<b>2. Esclusione di Garanzia:</b><br>"
            "Questo software viene fornito 'così com'è', senza garanzie esplicite o implicite di "
            "funzionamento o idoneità per scopi specifici.<br><br>"
            "<b>3. Limitazione di Responsabilità:</b><br>"
            "L'autore e NGV Group S.R.L. non potranno essere ritenuti responsabili per eventuali danni "
            "diretti, indiretti o incidentali derivanti dall'uso improprio di questa applicazione."
        )

        lbl_disc = QLabel(disc)
        lbl_disc.setWordWrap(True)
        lbl_disc.setFont(QFont("Segoe UI", 10))
        layout.addWidget(lbl_disc)

        layout.addStretch()

        btn_close = QPushButton("Ho Compreso")
        btn_close.setObjectName("PrimaryBtn")
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignRight)


class UpdateDialog(QDialog):
    def __init__(
        self,
        tag_version: str,
        download_url: str,
        release_notes: str,
        asset: Optional[Dict[str, Any]] = None,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Aggiornamento Disponibile")
        self.setFixedSize(520, 420)
        _set_window_icon(self)
        self.download_url = download_url
        self.tag_version = tag_version
        self.asset = asset if _can_self_update() else None
        self._downloader: Optional[UpdateDownloadThread] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)

        lbl_hdr = QLabel(f"🚀 È disponibile la nuova versione {tag_version}!")
        lbl_hdr.setFont(QFont("Segoe UI", 13, QFont.Bold))
        layout.addWidget(lbl_hdr)

        lbl_cur = QLabel(f"Versione attualmente installata: <b>v{APP_VERSION}</b>")
        lbl_cur.setFont(QFont("Segoe UI", 10))
        layout.addWidget(lbl_cur)

        layout.addWidget(QLabel("Note di rilascio:"))

        txt_notes = QTextEdit()
        txt_notes.setReadOnly(True)
        txt_notes.setPlainText(release_notes or "Nessuna nota di rilascio fornita.")
        txt_notes.setFont(QFont("Segoe UI", 9))
        layout.addWidget(txt_notes)

        self.prog = QProgressBar()
        self.prog.setFixedHeight(12)
        self.prog.setTextVisible(False)
        self.prog.hide()
        layout.addWidget(self.prog)

        self.lbl_state = QLabel("")
        self.lbl_state.setWordWrap(True)
        self.lbl_state.setTextFormat(Qt.PlainText)
        layout.addWidget(self.lbl_state)

        btn_box = QHBoxLayout()
        if self.asset:
            self.btn_download = QPushButton("⬇️ Aggiorna e riavvia")
            self.btn_download.clicked.connect(self._start_download)
        else:
            self.btn_download = QPushButton("🌐 Scarica Aggiornamento su GitHub")
            self.btn_download.clicked.connect(self._open_download)
        self.btn_download.setObjectName("PrimaryBtn")
        self.btn_download.setCursor(Qt.PointingHandCursor)

        self.btn_page = QPushButton("Pagina release")
        self.btn_page.setObjectName("SecondaryBtn")
        self.btn_page.setCursor(Qt.PointingHandCursor)
        self.btn_page.clicked.connect(self._open_download)
        self.btn_page.setVisible(bool(self.asset))

        self.btn_close = QPushButton("Più tardi" if self.asset else "Chiudi")
        self.btn_close.setObjectName("SecondaryBtn")
        self.btn_close.setCursor(Qt.PointingHandCursor)
        self.btn_close.clicked.connect(self.reject)

        btn_box.addWidget(self.btn_download)
        btn_box.addWidget(self.btn_page)
        btn_box.addStretch()
        btn_box.addWidget(self.btn_close)
        layout.addLayout(btn_box)

    def _open_download(self) -> None:
        QDesktopServices.openUrl(QUrl(self.download_url))
        self.accept()

    def _start_download(self) -> None:
        exe = _current_exe()
        dest = exe.with_name(exe.name + ".download")
        self.btn_download.setEnabled(False)
        self.btn_page.setEnabled(False)
        self.btn_close.setText("Annulla")
        self.prog.show()
        self.prog.setRange(0, 0)
        self.lbl_state.setText(f"Download di {self.tag_version} in corso...")
        self._downloader = UpdateDownloadThread(self.asset, dest)
        _keep_alive(self._downloader)
        self._downloader.progress.connect(self._on_progress)
        self._downloader.downloaded.connect(self._on_downloaded)
        self._downloader.failed.connect(self._on_failed)
        self._downloader.start()

    @Slot(int, int)
    def _on_progress(self, done: int, total: int) -> None:
        if total > 0:
            self.prog.setRange(0, 1000)
            self.prog.setValue(int(done * 1000 / total))
            self.lbl_state.setText(f"Download: {done / 1048576:.1f} di {total / 1048576:.1f} MB")

    @Slot(str)
    def _on_downloaded(self, path: str) -> None:
        self.lbl_state.setText("Download verificato. Installazione e riavvio...")
        exe = _current_exe()
        try:
            _install_update(pathlib.Path(path), exe)
            _launch_detached(exe)
        except OSError as e:
            self._on_failed(f"impossibile sostituire {exe.name}: {e}")
            return
        self.accept()
        QApplication.instance().quit()

    @Slot(str)
    def _on_failed(self, err: str) -> None:
        self.prog.hide()
        self.lbl_state.setText(f"Aggiornamento non riuscito: {err}\nPuoi scaricarlo dalla pagina della release.")
        self.btn_download.setEnabled(True)
        self.btn_page.setEnabled(True)
        self.btn_close.setText("Chiudi")

    def done(self, result: int) -> None:
        if self._downloader is not None and self._downloader.isRunning():
            self._downloader.cancel.set()
        super().done(result)


# --- MAIN APPLICATION WINDOW ---

class LanScannerWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} — Material 3 Edition")
        self.resize(1240, 720)
        self.setMinimumSize(920, 540)

        _set_window_icon(self)

        self.settings = QSettings("NGVGroup", "LanScanner")
        self.theme_mode = self.settings.value("theme_mode", "auto")
        self.scan_worker: Optional[ScanWorkerThread] = None
        self.update_checker: Optional[UpdateCheckerThread] = None
        self._row_items: Dict[str, QTreeWidgetItem] = {}

        self._load_device_notes()

        self._create_menu_bar()
        self._init_ui()
        self._apply_theme()
        self._update_recent_menu()
        self._populate_network_adapters()

        QTimer.singleShot(2500, lambda: self.check_for_updates(manual=False))
        # Il processo della versione precedente può impiegare qualche secondo a chiudersi e liberare il .old
        _cleanup_previous_update()
        QTimer.singleShot(8000, _cleanup_previous_update)

    def _load_device_notes(self) -> None:
        raw = self.settings.value("device_notes", "{}")
        try:
            self.device_notes: Dict[str, str] = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            self.device_notes = {}

    def _save_device_notes(self) -> None:
        self.settings.setValue("device_notes", json.dumps(self.device_notes))

    # --- THEME ENGINE ---
    def _get_effective_theme(self) -> str:
        if self.theme_mode == "light":
            return "light"
        elif self.theme_mode == "dark":
            return "dark"
        else:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                )
                val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                winreg.CloseKey(key)
                return "light" if val == 1 else "dark"
            except Exception:
                return "dark"

    def set_theme_mode(self, mode: str) -> None:
        self.theme_mode = mode
        self.settings.setValue("theme_mode", mode)
        self._update_theme_menu_checks()
        self._apply_theme()

    def _update_theme_menu_checks(self) -> None:
        if hasattr(self, "act_theme_light"):
            self.act_theme_light.setChecked(self.theme_mode == "light")
            self.act_theme_dark.setChecked(self.theme_mode == "dark")
            self.act_theme_auto.setChecked(self.theme_mode == "auto")

        if hasattr(self, "btn_theme_quick"):
            if self.theme_mode == "light":
                self.btn_theme_quick.setText("☀️ Chiaro")
            elif self.theme_mode == "dark":
                self.btn_theme_quick.setText("🌙 Scuro")
            else:
                self.btn_theme_quick.setText("💻 Auto")

    # --- RECENT RANGES PERSISTENCE ---
    def get_recent_ranges(self) -> List[Tuple[str, str]]:
        raw = self.settings.value("recent_ranges", [])
        if isinstance(raw, list):
            res = []
            for item in raw:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    res.append((str(item[0]), str(item[1])))
            return res[:8]
        return []

    def add_recent_range(self, start_ip: str, end_ip: str) -> None:
        ranges = self.get_recent_ranges()
        pair = (start_ip, end_ip)
        if pair in ranges:
            ranges.remove(pair)
        ranges.insert(0, pair)
        ranges = ranges[:8]
        self.settings.setValue("recent_ranges", ranges)
        self._update_recent_menu()

    def clear_recent_ranges(self) -> None:
        self.settings.setValue("recent_ranges", [])
        self._update_recent_menu()
        self.lbl_status_msg.setText("Cronologia intervalli recenti svuotata.")

    # --- MENU BAR ---
    def _create_menu_bar(self) -> None:
        menu_bar = self.menuBar()

        # File Menu
        menu_file = menu_bar.addMenu("&File")

        act_scan = QAction("🔍 Avvia Nuova Scansione", self)
        act_scan.setShortcut(QKeySequence("Ctrl+R"))
        act_scan.triggered.connect(self._start_scan)
        menu_file.addAction(act_scan)

        act_sub = QAction("🌐 Imposta Subnet Locale Auto", self)
        act_sub.triggered.connect(self._set_local_subnet)
        menu_file.addAction(act_sub)

        self.menu_recent = menu_file.addMenu("🕒 Intervalli Recenti")

        menu_file.addSeparator()

        self.act_export_csv = QAction("💾 Esporta Risultati CSV...", self)
        self.act_export_csv.setShortcut(QKeySequence.Save)
        self.act_export_csv.triggered.connect(self._export_csv_dialog)
        menu_file.addAction(self.act_export_csv)

        self.act_export_json = QAction("📄 Esporta Risultati JSON...", self)
        self.act_export_json.triggered.connect(self._export_json_dialog)
        menu_file.addAction(self.act_export_json)

        self.act_export_html = QAction("🌐 Esporta Report HTML Interattivo...", self)
        self.act_export_html.triggered.connect(self._export_html_dialog)
        menu_file.addAction(self.act_export_html)

        self.act_print = QAction("🖨️ Stampa Report...", self)
        self.act_print.setShortcut(QKeySequence.Print)
        self.act_print.triggered.connect(self._print_report)
        menu_file.addAction(self.act_print)

        menu_file.addSeparator()

        act_exit = QAction("🚪 Esci", self)
        act_exit.setShortcut(QKeySequence("Ctrl+Q"))
        act_exit.triggered.connect(self.close)
        menu_file.addAction(act_exit)

        # Strumenti Menu
        menu_tools = menu_bar.addMenu("&Strumenti")

        menu_theme = menu_tools.addMenu("🎨 Tema Interfaccia")
        theme_group = QActionGroup(self)
        theme_group.setExclusive(True)

        self.act_theme_light = QAction("☀️ Chiaro", self, checkable=True)
        self.act_theme_light.triggered.connect(lambda: self.set_theme_mode("light"))
        theme_group.addAction(self.act_theme_light)
        menu_theme.addAction(self.act_theme_light)

        self.act_theme_dark = QAction("🌙 Scuro", self, checkable=True)
        self.act_theme_dark.triggered.connect(lambda: self.set_theme_mode("dark"))
        theme_group.addAction(self.act_theme_dark)
        menu_theme.addAction(self.act_theme_dark)

        self.act_theme_auto = QAction("💻 Automatico (Sistema)", self, checkable=True)
        self.act_theme_auto.triggered.connect(lambda: self.set_theme_mode("auto"))
        theme_group.addAction(self.act_theme_auto)
        menu_theme.addAction(self.act_theme_auto)

        self._update_theme_menu_checks()

        menu_tools.addSeparator()

        act_subnet_calc = QAction("🌐 Calcolatore Subnet / Notazione CIDR...", self)
        act_subnet_calc.triggered.connect(self._open_subnet_calc)
        menu_tools.addAction(act_subnet_calc)

        act_copy = QAction("📋 Copia Righe Selezionate", self)
        act_copy.setShortcut(QKeySequence.Copy)
        act_copy.triggered.connect(self._copy_selection)
        menu_tools.addAction(act_copy)

        act_ping_cont = QAction("📈 Ping Continuo & Latenza...", self)
        act_ping_cont.triggered.connect(self._open_continuous_ping_selected)
        menu_tools.addAction(act_ping_cont)

        act_custom_port = QAction("🎯 Scansione Porte Personalizzata...", self)
        act_custom_port.triggered.connect(self._open_custom_port_scan_selected)
        menu_tools.addAction(act_custom_port)

        act_trace = QAction("🛤️ Visualizza Traceroute (Rotta IP)...", self)
        act_trace.triggered.connect(self._open_traceroute_selected)
        menu_tools.addAction(act_trace)

        act_note = QAction("✏️ Assegna / Modifica Nota Dispositivo...", self)
        act_note.triggered.connect(self._edit_note_selected)
        menu_tools.addAction(act_note)

        act_detail = QAction("🔍 Dettaglio Dispositivo...", self)
        act_detail.triggered.connect(self._open_detail_selected)
        menu_tools.addAction(act_detail)

        # Help Menu
        menu_help = menu_bar.addMenu("&?")

        act_update = QAction("🔄 Controlla Aggiornamenti...", self)
        act_update.triggered.connect(lambda: self.check_for_updates(manual=True))
        menu_help.addAction(act_update)

        act_website = QAction("🌐 Visita vcuria.app (Sito Autore)", self)
        act_website.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(WEBSITE_URL)))
        menu_help.addAction(act_website)

        menu_help.addSeparator()

        act_info = QAction("ℹ️ Informazioni e Crediti", self)
        act_info.triggered.connect(lambda: _exec_dialog(AboutDialog(self)))
        menu_help.addAction(act_info)

        act_legal = QAction("⚖️ Avviso di Responsabilità Legale", self)
        act_legal.triggered.connect(lambda: _exec_dialog(LegalDisclaimerDialog(self)))
        menu_help.addAction(act_legal)

    def _update_recent_menu(self) -> None:
        self.menu_recent.clear()
        recent = self.get_recent_ranges()

        if not recent:
            no_act = QAction("Nessun intervallo recente", self)
            no_act.setEnabled(False)
            self.menu_recent.addAction(no_act)
            return

        for s_ip, e_ip in recent:
            label = f"🌐 {s_ip}  →  {e_ip}"
            act = QAction(label, self)
            act.triggered.connect(lambda checked=False, s=s_ip, e=e_ip: self._apply_recent_range(s, e))
            self.menu_recent.addAction(act)

        self.menu_recent.addSeparator()
        act_clear = QAction("🗑️ Svuota Cronologia Recenti", self)
        act_clear.triggered.connect(self.clear_recent_ranges)
        self.menu_recent.addAction(act_clear)

    def _apply_recent_range(self, start_ip: str, end_ip: str) -> None:
        self.txt_ip_start.setText(start_ip)
        self.txt_ip_end.setText(end_ip)
        self.lbl_status_msg.setText(f"Impostato intervallo recente: {start_ip} - {end_ip}")

    # --- UI INITIALIZATION ---
    def _init_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)

        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 8, 10, 6)
        main_layout.setSpacing(8)

        # TOP BAR MATERIAL 3
        top_bar = QFrame()
        top_bar.setObjectName("TopBar")
        top_bar.setFixedHeight(52)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(12, 4, 12, 4)
        top_layout.setSpacing(10)

        logo_layout = QHBoxLayout()
        logo_layout.setSpacing(8)

        lbl_icon = QLabel("📡")
        lbl_icon.setFont(QFont("Segoe UI Emoji", 15))

        lbl_title = QLabel(APP_NAME)
        lbl_title.setObjectName("BrandTitle")

        chip_ver = QLabel(f"v{APP_VERSION} M3")
        chip_ver.setObjectName("M3VersionChip")

        logo_layout.addWidget(lbl_icon)
        logo_layout.addWidget(lbl_title)
        logo_layout.addWidget(chip_ver)

        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setObjectName("VerticalSeparator")

        self.btn_scan = QPushButton("🔍 Scansiona")
        self.btn_scan.setObjectName("PrimaryBtn")
        self.btn_scan.setCursor(Qt.PointingHandCursor)
        self.btn_scan.clicked.connect(self._on_scan_button_clicked)

        self.btn_export = QPushButton("💾 Esporta CSV")
        self.btn_export.setObjectName("SecondaryBtn")
        self.btn_export.setCursor(Qt.PointingHandCursor)
        self.btn_export.clicked.connect(self._export_csv_dialog)

        self.btn_print = QPushButton("🖨️ Stampa")
        self.btn_print.setObjectName("SecondaryBtn")
        self.btn_print.setCursor(Qt.PointingHandCursor)
        self.btn_print.clicked.connect(self._print_report)

        self.btn_theme_quick = QToolButton()
        self.btn_theme_quick.setObjectName("ThemeToolBtn")
        self.btn_theme_quick.setPopupMode(QToolButton.InstantPopup)
        self.btn_theme_quick.setCursor(Qt.PointingHandCursor)

        menu_quick_theme = QMenu(self)
        act_l = menu_quick_theme.addAction("☀️ Chiaro")
        act_l.triggered.connect(lambda: self.set_theme_mode("light"))
        act_d = menu_quick_theme.addAction("🌙 Scuro")
        act_d.triggered.connect(lambda: self.set_theme_mode("dark"))
        act_a = menu_quick_theme.addAction("💻 Automatico")
        act_a.triggered.connect(lambda: self.set_theme_mode("auto"))
        self.btn_theme_quick.setMenu(menu_quick_theme)

        self._update_theme_menu_checks()

        author_badge = QLabel("Vincenzo Curia • Software Gratuito")
        author_badge.setObjectName("AuthorBadge")

        top_layout.addLayout(logo_layout)
        top_layout.addWidget(sep)
        top_layout.addWidget(self.btn_scan)
        top_layout.addWidget(self.btn_export)
        top_layout.addWidget(self.btn_print)
        top_layout.addStretch()
        top_layout.addWidget(self.btn_theme_quick)
        top_layout.addWidget(author_badge)

        main_layout.addWidget(top_bar)

        # MAIN CARD AREA
        card_scan = QFrame()
        card_scan.setObjectName("InfoCard")
        card_layout = QVBoxLayout(card_scan)
        card_layout.setContentsMargins(12, 10, 12, 10)
        card_layout.setSpacing(10)

        # Controls & Adapter Selector Row
        row_inputs = QHBoxLayout()
        row_inputs.setSpacing(10)

        lbl_adapter = QLabel("Scheda:")
        lbl_adapter.setFont(QFont("Segoe UI", 9.5, QFont.Bold))
        self.cmb_adapters = QComboBox()
        self.cmb_adapters.setFixedWidth(200)
        self.cmb_adapters.currentIndexChanged.connect(self._on_adapter_selected)

        lbl_s = QLabel("IP Iniziale / CIDR:")
        lbl_s.setFont(QFont("Segoe UI", 9.5, QFont.Bold))
        self.txt_ip_start = QLineEdit()
        self.txt_ip_start.setFixedWidth(135)
        self.txt_ip_start.setFont(QFont("Consolas", 10))
        self.txt_ip_start.textChanged.connect(self._on_ip_start_changed)

        lbl_e = QLabel("IP Finale:")
        lbl_e.setFont(QFont("Segoe UI", 9.5, QFont.Bold))
        self.txt_ip_end = QLineEdit()
        self.txt_ip_end.setFixedWidth(120)
        self.txt_ip_end.setFont(QFont("Consolas", 10))

        def_a, def_b = _default_range()
        self.txt_ip_start.setText(def_a)
        self.txt_ip_end.setText(def_b)

        btn_auto_sub = QPushButton("🌐 Auto Subnet")
        btn_auto_sub.setObjectName("ControlBtn")
        btn_auto_sub.setCursor(Qt.PointingHandCursor)
        btn_auto_sub.clicked.connect(self._set_local_subnet)

        btn_cidr_info = QPushButton("📐 Subnet Info")
        btn_cidr_info.setObjectName("ControlBtn")
        btn_cidr_info.setCursor(Qt.PointingHandCursor)
        btn_cidr_info.clicked.connect(self._open_subnet_calc)

        row_inputs.addWidget(lbl_adapter)
        row_inputs.addWidget(self.cmb_adapters)
        row_inputs.addWidget(lbl_s)
        row_inputs.addWidget(self.txt_ip_start)
        row_inputs.addWidget(lbl_e)
        row_inputs.addWidget(self.txt_ip_end)
        row_inputs.addWidget(btn_auto_sub)
        row_inputs.addWidget(btn_cidr_info)

        row_inputs.addSpacing(10)

        # Search filter in table
        lbl_filter = QLabel("🔎 Filtra:")
        lbl_filter.setFont(QFont("Segoe UI", 9.5))
        self.txt_filter = QLineEdit()
        self.txt_filter.setPlaceholderText("Cerca IP, MAC, Hostname, Note...")
        self.txt_filter.setFont(QFont("Segoe UI", 9.5))
        self.txt_filter.textChanged.connect(self._apply_filter)

        row_inputs.addWidget(lbl_filter)
        row_inputs.addWidget(self.txt_filter)

        card_layout.addLayout(row_inputs)

        # Progress bar
        self.prog_bar = QProgressBar()
        self.prog_bar.setFixedHeight(12)
        self.prog_bar.setTextVisible(False)
        card_layout.addWidget(self.prog_bar)

        # Results Table Widget
        self.table = QTreeWidget()
        self.table.setColumnCount(len(COL_HEADERS))
        self.table.setHeaderLabels(COL_HEADERS)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setRootIsDecorated(False)
        self.table.setUniformRowHeights(True)

        header = self.table.header()
        for idx, width in enumerate(COL_WIDTHS):
            self.table.setColumnWidth(idx, width)
        header.setStretchLastSection(True)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.itemDoubleClicked.connect(self._on_table_double_click)

        card_layout.addWidget(self.table)

        main_layout.addWidget(card_scan)

        # FOOTER BAR
        footer_bar = QFrame()
        footer_bar.setObjectName("FooterBar")
        footer_bar.setFixedHeight(26)
        footer_layout = QHBoxLayout(footer_bar)
        footer_layout.setContentsMargins(10, 1, 10, 1)

        self.lbl_status_msg = QLabel("Pronto — Inserisci un intervallo IP o notazione CIDR ed avvia la scansione")
        self.lbl_status_msg.setObjectName("FooterStatus")

        lbl_credits = QLabel(
            f"{APP_NAME} • <a href='{WEBSITE_URL}' style='text-decoration:none;'>Vincenzo Curia ({WEBSITE_URL})</a> | {APP_COMPANY}"
        )
        lbl_credits.setObjectName("FooterCredits")
        lbl_credits.setOpenExternalLinks(True)

        footer_layout.addWidget(self.lbl_status_msg)
        footer_layout.addStretch()
        footer_layout.addWidget(lbl_credits)

        main_layout.addWidget(footer_bar)

    def _populate_network_adapters(self) -> None:
        adapters = _get_network_interfaces()
        local_ip = _local_ipv4()
        self.cmb_adapters.blockSignals(True)
        self.cmb_adapters.clear()
        for name, ip, prefix in adapters:
            self.cmb_adapters.addItem(f"{name} ({ip}/{prefix})", userData=(ip, prefix))
            self.cmb_adapters.setItemData(self.cmb_adapters.count() - 1, f"{name}\n{ip}/{prefix}", Qt.ToolTipRole)
            if ip == local_ip:
                # La scheda della rotta predefinita è quella dell'intervallo proposto all'avvio
                self.cmb_adapters.setCurrentIndex(self.cmb_adapters.count() - 1)
        self.cmb_adapters.blockSignals(False)

    def _on_adapter_selected(self, index: int) -> None:
        data = self.cmb_adapters.itemData(index)
        if data:
            ip, prefix = data
            s_a, s_b = _default_range_for_ip(ip, prefix)
            self.txt_ip_start.setText(s_a)
            self.txt_ip_end.setText(s_b)
            self.lbl_status_msg.setText(f"Selezionata scheda: {ip}/{prefix} → Intervallo: {s_a} - {s_b}")

    def _on_ip_start_changed(self, text: str) -> None:
        txt = text.strip()
        if "/" in txt:
            try:
                net = ipaddress.IPv4Network(txt, strict=False)
                hosts = list(net.hosts())
                if hosts:
                    self.txt_ip_end.setText(str(hosts[-1]))
            except ValueError:
                pass

    # --- SCAN LOGIC & WORKER ---

    def _set_local_subnet(self) -> None:
        a, b = _default_range()
        self.txt_ip_start.setText(a)
        self.txt_ip_end.setText(b)
        self.lbl_status_msg.setText(f"Rilevata subnet locale: {a} - {b}")

    def _open_subnet_calc(self) -> None:
        cidr_str = self.txt_ip_start.text().strip()
        _exec_dialog(SubnetCalculatorDialog(cidr_str, self))

    def _on_scan_button_clicked(self) -> None:
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.lbl_status_msg.setText("Interruzione scansione in corso...")
            self.btn_scan.setEnabled(False)
            return

        self._start_scan()

    def _start_scan(self) -> None:
        s0 = self.txt_ip_start.text().strip()
        s1 = self.txt_ip_end.text().strip()

        try:
            hosts = _parse_ip_input(s0, s1)
        except Exception as e:
            QMessageBox.critical(self, "Errore Intervallo IP", f"Impossibile interpretare l'intervallo IP/CIDR: {e}")
            return

        if not hosts:
            QMessageBox.critical(self, "Errore", "Nessun indirizzo IP valido nell'intervallo specificato.")
            return

        self.add_recent_range(s0, s1)
        self.table.clear()
        self._row_items: Dict[str, QTreeWidgetItem] = {}
        self.prog_bar.setMaximum(len(hosts))
        self.prog_bar.setValue(0)

        self.btn_scan.setText("🛑 Interrompi")
        self.btn_scan.setEnabled(True)
        self.lbl_status_msg.setText(f"Scansione ICMP Nativa + ARP Cache su {len(hosts)} host IPv4 in corso...")

        self.scan_worker = ScanWorkerThread(hosts, self.device_notes, max_workers=64)
        self.scan_worker.progress_updated.connect(self._on_scan_progress)
        self.scan_worker.initial_alive_found.connect(self._on_initial_alive)
        self.scan_worker.hostname_resolved.connect(self._on_hostname_resolved)
        self.scan_worker.names_progress.connect(self._on_names_progress)
        self.scan_worker.scan_finished.connect(self._on_scan_finished)
        self.scan_worker.scan_interrupted.connect(self._on_scan_interrupted)
        self.scan_worker.scan_error.connect(self._on_scan_error)
        self.scan_worker.start()

    @Slot(int, int)
    def _on_scan_progress(self, done: int, total: int) -> None:
        self.prog_bar.setValue(done)
        self.lbl_status_msg.setText(f"Scansione Ping Nativa in corso: {done}/{total} host verificati...")

    @Slot(list)
    def _on_initial_alive(self, rows: List[Tuple[str, str, str, str, str, str, str]]) -> None:
        for r in rows:
            item = QTreeWidgetItem(self.table, list(r))
            item.setTextAlignment(1, Qt.AlignCenter)
            self._row_items[r[0]] = item
        self._apply_filter(self.txt_filter.text())
        self.lbl_status_msg.setText(f"Trovati {len(rows)} host: risoluzione nomi in corso...")

    @Slot(str, str, str, str)
    def _on_hostname_resolved(self, ip: str, hostname: str, hint: str, note: str) -> None:
        item = self._row_items.get(ip)
        if item is not None:
            item.setText(4, hostname)
            item.setText(5, hint)
            item.setText(6, note)
            # Il nome appena arrivato può far rientrare la riga nel filtro attivo
            self._filter_item(item, self.txt_filter.text().strip().lower())

    @Slot(int, int)
    def _on_names_progress(self, done: int, total: int) -> None:
        self.lbl_status_msg.setText(f"Risoluzione nomi (DNS, mDNS, UPnP): {done}/{total} host...")

    @Slot(int)
    def _on_scan_finished(self, total_alive: int) -> None:
        self.prog_bar.setValue(self.prog_bar.maximum())
        self.btn_scan.setText("🔍 Scansiona")
        self.btn_scan.setEnabled(True)
        self.lbl_status_msg.setText(f"Scansione completata con successo: trovati {total_alive} host attivi nella LAN.")

    @Slot()
    def _on_scan_interrupted(self) -> None:
        self.btn_scan.setText("🔍 Scansiona")
        self.btn_scan.setEnabled(True)
        self.lbl_status_msg.setText("Scansione interrotta dall'utente.")

    @Slot(str)
    def _on_scan_error(self, err_msg: str) -> None:
        self.btn_scan.setText("🔍 Scansiona")
        self.btn_scan.setEnabled(True)
        self.lbl_status_msg.setText("Errore durante la scansione.")
        QMessageBox.critical(self, "Errore Scansione", f"Si è verificato un errore: {err_msg}")

    def closeEvent(self, event) -> None:
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait(3000)
        super().closeEvent(event)

    # --- FILTERING & CONTEXT MENU ---
    def _filter_item(self, item: QTreeWidgetItem, query: str) -> None:
        match = not query or any(query in item.text(c).lower() for c in range(item.columnCount()))
        item.setHidden(not match)

    def _apply_filter(self, text: str) -> None:
        query = text.strip().lower()
        root = self.table.invisibleRootItem()
        for i in range(root.childCount()):
            self._filter_item(root.child(i), query)

    def _show_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        menu = QMenu(self)

        act_copy = menu.addAction("📋 Copia Selezione")
        act_copy.triggered.connect(self._copy_selection)

        if item:
            ip = item.text(0)
            mac = item.text(2)

            menu.addSeparator()

            act_web = menu.addAction(f"🌐 Apri Web Browser (http://{ip})")
            act_web.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(f"http://{ip}")))

            act_webs = menu.addAction(f"🔒 Apri Web Sicuro (https://{ip})")
            act_webs.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(f"https://{ip}")))

            act_rdp = menu.addAction("🖥️ Connetti via Desktop Remoto (RDP)")
            act_rdp.triggered.connect(lambda: self._launch_rdp(ip))

            act_ssh = menu.addAction("💻 Terminale SSH (ssh user@ip)")
            act_ssh.triggered.connect(lambda: self._launch_ssh(ip))

            act_smb = menu.addAction(f"📁 Apri Condivisione File (SMB - \\\\{ip})")
            act_smb.triggered.connect(lambda: self._launch_smb(ip))

            if mac and mac != "—":
                act_wol = menu.addAction("⚡ Invia Pacchetto Wake-on-LAN (WoL)")
                act_wol.triggered.connect(lambda: self._trigger_wol(mac, ip))

            menu.addSeparator()

            act_ping_cont = menu.addAction("📈 Monitor Latenza & Ping Continuo...")
            act_ping_cont.triggered.connect(lambda: _exec_dialog(ContinuousPingDialog(ip, self)))

            act_custom_p = menu.addAction("🎯 Scansione Porte Personalizzata...")
            act_custom_p.triggered.connect(lambda: _exec_dialog(CustomPortScanDialog(ip, self)))

            act_trace = menu.addAction("🛤️ Visualizza Traceroute (Rotta IP)...")
            act_trace.triggered.connect(lambda: _exec_dialog(TracerouteDialog(ip, self)))

            act_note = menu.addAction("✏️ Assegna / Modifica Nota Dispositivo...")
            act_note.triggered.connect(lambda: self._edit_note_item(item))

            act_det = menu.addAction("🔍 Dettaglio Completo Dispositivo...")
            act_det.triggered.connect(lambda: self._open_detail_item(item))

        menu.addSeparator()

        act_exp_all_csv = menu.addAction("💾 Esporta Tutti i Risultati in CSV")
        act_exp_all_csv.triggered.connect(lambda: self._export_csv_action(only_selected=False))

        act_exp_json = menu.addAction("📄 Esporta Tutti i Risultati in JSON")
        act_exp_json.triggered.connect(lambda: self._export_json_action(only_selected=False))

        act_exp_html = menu.addAction("🌐 Esporta Report HTML Interattivo")
        act_exp_html.triggered.connect(lambda: self._export_html_action(only_selected=False))

        menu.addSeparator()
        act_info = menu.addAction("ℹ️ Informazioni e Crediti")
        act_info.triggered.connect(lambda: _exec_dialog(AboutDialog(self)))

        menu.exec(self.table.mapToGlobal(pos))

    def _launch_rdp(self, ip: str) -> None:
        try:
            subprocess.Popen(["mstsc", f"/v:{ip}"])
            self.lbl_status_msg.setText(f"Avviata connessione Desktop Remoto a {ip}...")
        except Exception as e:
            QMessageBox.critical(self, "RDP", f"Impossibile avviare RDP: {e}")

    def _launch_ssh(self, ip: str) -> None:
        try:
            subprocess.Popen(["cmd.exe", "/c", "start", "cmd.exe", "/k", f"ssh {ip}"])
            self.lbl_status_msg.setText(f"Avviata sessione SSH per {ip}...")
        except Exception as e:
            QMessageBox.critical(self, "SSH", f"Impossibile aprire il terminale SSH: {e}")

    def _launch_smb(self, ip: str) -> None:
        try:
            subprocess.Popen(["explorer", f"\\\\{ip}"])
            self.lbl_status_msg.setText(f"Apertura condivisione file \\\\{ip}...")
        except Exception as e:
            QMessageBox.critical(self, "SMB", f"Impossibile aprire la cartella condivisa: {e}")

    def _trigger_wol(self, mac: str, ip: str) -> None:
        if _send_wol(mac):
            self.lbl_status_msg.setText(f"Pacchetto Wake-on-LAN inviato al MAC {mac} ({ip}).")
            QMessageBox.information(self, "Wake-on-LAN", f"Pacchetto Magic Packet WoL inviato con successo a {ip} ({mac}).")
        else:
            QMessageBox.warning(self, "Wake-on-LAN", f"Impossibile inviare il pacchetto WoL al MAC {mac}.")

    def _on_table_double_click(self, item: QTreeWidgetItem, column: int) -> None:
        self._open_detail_item(item)

    def _open_detail_selected(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Dettaglio", "Seleziona una riga dalla tabella.")
            return
        self._open_detail_item(selected[0])

    def _open_continuous_ping_selected(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Ping Continuo", "Seleziona una riga dalla tabella.")
            return
        ip = selected[0].text(0)
        _exec_dialog(ContinuousPingDialog(ip, self))

    def _open_custom_port_scan_selected(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Port Scan", "Seleziona una riga dalla tabella.")
            return
        ip = selected[0].text(0)
        _exec_dialog(CustomPortScanDialog(ip, self))

    def _open_traceroute_selected(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Traceroute", "Seleziona una riga dalla tabella.")
            return
        ip = selected[0].text(0)
        _exec_dialog(TracerouteDialog(ip, self))

    def _edit_note_selected(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Nota Utente", "Seleziona una riga dalla tabella.")
            return
        self._edit_note_item(selected[0])

    def _edit_note_item(self, item: QTreeWidgetItem) -> None:
        ip = item.text(0)
        mac = item.text(2)
        old_note = item.text(6) if item.columnCount() > 6 else ""
        if old_note == "—":
            old_note = ""

        new_note, ok = QInputDialog.getText(
            self,
            "Nota Personalizzata Dispositivo",
            f"Inserisci o modifica la nota per l'host {ip} (MAC: {mac}):",
            QLineEdit.Normal,
            old_note,
        )
        if ok:
            note_txt = new_note.strip()
            key = mac if (mac and mac != "—") else ip
            if note_txt:
                self.device_notes[key] = note_txt
            else:
                self.device_notes.pop(key, None)
            self._save_device_notes()
            item.setText(6, note_txt or "—")
            self.lbl_status_msg.setText(f"Nota aggiornata per {ip}.")

    def _open_detail_item(self, item: QTreeWidgetItem) -> None:
        values = tuple(item.text(i) for i in range(item.columnCount()))
        if values:
            _exec_dialog(DeviceDetailDialog(values[0], values, self))

    def _copy_selection(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            self.lbl_status_msg.setText("Nessuna riga selezionata da copiare.")
            return

        lines = []
        for item in selected:
            row_vals = [item.text(i) for i in range(item.columnCount())]
            lines.append("\t".join(row_vals))

        cb = QApplication.clipboard()
        cb.setText("\n".join(lines))
        self.lbl_status_msg.setText(f"Copiate {len(selected)} righe negli appunti.")

    # --- EXPORTS & PRINTING ---

    def _export_csv_dialog(self) -> None:
        self._export_csv_action(only_selected=False)

    def _export_json_dialog(self) -> None:
        self._export_json_action(only_selected=False)

    def _export_html_dialog(self) -> None:
        self._export_html_action(only_selected=False)

    def _get_export_items(self, only_selected: bool) -> List[QTreeWidgetItem]:
        root = self.table.invisibleRootItem()
        return self.table.selectedItems() if only_selected else [root.child(i) for i in range(root.childCount())]

    def _export_csv_action(self, only_selected: bool = False) -> None:
        items = self._get_export_items(only_selected)
        if not items:
            QMessageBox.warning(self, "Esporta CSV", "Nessun dato presente da esportare.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Esporta Risultati Scansione",
            "LanScanner_Results.csv",
            "File CSV (*.csv);;Tutti i file (*.*)",
        )

        if not filename:
            return

        try:
            with open(filename, "w", newline="", encoding="utf-8-sig") as fp:
                writer = csv.writer(fp, delimiter=";")
                writer.writerow(COL_HEADERS)
                for item in items:
                    writer.writerow([item.text(i) for i in range(item.columnCount())])

            self.lbl_status_msg.setText(f"Esportazione CSV completata: {filename}")
            QMessageBox.information(self, "Esportazione CSV", f"File esportato con successo:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Errore Esportazione", f"Impossibile salvare il file: {e}")

    def _export_json_action(self, only_selected: bool = False) -> None:
        items = self._get_export_items(only_selected)
        if not items:
            QMessageBox.warning(self, "Esporta JSON", "Nessun dato presente da esportare.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Esporta Risultati in JSON",
            "LanScanner_Results.json",
            "File JSON (*.json);;Tutti i file (*.*)",
        )
        if not filename:
            return

        try:
            records = []
            for item in items:
                records.append({
                    "ip": item.text(0),
                    "status": item.text(1),
                    "mac": item.text(2),
                    "vendor": item.text(3),
                    "hostname": item.text(4),
                    "hint": item.text(5),
                    "note": item.text(6) if item.columnCount() > 6 else "",
                })

            export_data = {
                "app": APP_NAME,
                "version": APP_VERSION,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_hosts": len(records),
                "hosts": records,
            }

            with open(filename, "w", encoding="utf-8") as fp:
                json.dump(export_data, fp, indent=2, ensure_ascii=False)

            self.lbl_status_msg.setText(f"Esportazione JSON completata: {filename}")
            QMessageBox.information(self, "Esportazione JSON", f"File esportato con successo:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Errore Esportazione", f"Impossibile salvare il file: {e}")

    def _export_html_action(self, only_selected: bool = False) -> None:
        items = self._get_export_items(only_selected)
        if not items:
            QMessageBox.warning(self, "Esporta HTML", "Nessun dato presente da esportare.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Esporta Report HTML Interattivo",
            "LanScanner_Report.html",
            "File HTML (*.html);;Tutti i file (*.*)",
        )
        if not filename:
            return

        try:
            rows_html = []
            for idx, item in enumerate(items):
                bg = "#ffffff" if idx % 2 == 0 else "#f8fafc"
                # Hostname, banner UPnP e note arrivano dalla rete o dall'utente: vanno escapati
                cols = "".join(f"<td>{html.escape(item.text(c))}</td>" for c in range(item.columnCount()))
                rows_html.append(f"<tr style='background-color:{bg};'>{cols}</tr>")

            headers_html = "".join(f"<th>{h}</th>" for h in COL_HEADERS)

            html_content = f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>LanScanner v{APP_VERSION} — Report Scansione LAN</title>
    <style>
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
        .card {{ background-color: #1e293b; border-radius: 14px; padding: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); border: 1px solid #334155; }}
        h1 {{ margin-top: 0; color: #38bdf8; font-size: 24px; display: flex; align-items: center; gap: 10px; }}
        .meta {{ color: #94a3b8; font-size: 13px; margin-bottom: 20px; }}
        input {{ width: 100%; max-width: 400px; padding: 10px 14px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #fff; margin-bottom: 16px; font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; border-radius: 10px; overflow: hidden; }}
        th {{ background-color: #334155; color: #38bdf8; text-align: left; padding: 12px; font-size: 13px; }}
        td {{ padding: 10px 12px; color: #0f172a; font-size: 13px; border-bottom: 1px solid #e2e8f0; }}
        tr:hover {{ background-color: #e0f2fe !important; }}
        footer {{ margin-top: 24px; font-size: 11px; color: #64748b; text-align: center; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>📡 LanScanner v{APP_VERSION} — Report Scansione LAN</h1>
        <div class="meta">
            <b>Data Generazione:</b> {time.strftime('%d/%m/%Y %H:%M:%S')} | 
            <b>Host Rilevati:</b> {len(items)} | 
            <b>Autore:</b> {APP_DEVELOPER} ({APP_COMPANY})
        </div>
        <input type="text" id="search" onkeyup="filterTable()" placeholder="🔎 Cerca IP, Hostname, Vendor, MAC, Note...">
        <table id="results">
            <thead><tr>{headers_html}</tr></thead>
            <tbody>{"".join(rows_html)}</tbody>
        </table>
    </div>
    <footer>Generato da LanScanner Portable • <a href="{WEBSITE_URL}" style="color:#38bdf8;">vcuria.app</a></footer>
    <script>
        function filterTable() {{
            var input = document.getElementById("search").value.toLowerCase();
            var rows = document.querySelectorAll("#results tbody tr");
            rows.forEach(function(row) {{
                row.style.display = row.innerText.toLowerCase().includes(input) ? "" : "none";
            }});
        }}
    </script>
</body>
</html>"""
            with open(filename, "w", encoding="utf-8") as fp:
                fp.write(html_content)

            self.lbl_status_msg.setText(f"Esportazione HTML completata: {filename}")
            QMessageBox.information(self, "Esportazione HTML", f"Report HTML generato con successo:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Errore Esportazione", f"Impossibile salvare il report HTML: {e}")

    def _print_report(self) -> None:
        root = self.table.invisibleRootItem()
        count = root.childCount()
        if count == 0:
            QMessageBox.warning(self, "Stampa", "Nessun dato disponibile da stampare.")
            return

        printer = QPrinter(QPrinter.HighResolution)
        dialog = QPrintDialog(printer, self)
        if dialog.exec() == QPrintDialog.Accepted:
            parts = [
                f"<h2>{APP_NAME} — Report Scansione LAN</h2>",
                f"<p><b>Data:</b> {time.strftime('%d/%m/%Y %H:%M')} | <b>Host Trovati:</b> {count}</p>",
                "<table border='1' cellspacing='0' cellpadding='5' style='border-collapse:collapse; width:100%; font-family: Segoe UI, sans-serif;'>",
                "<tr bgcolor='#f1f5f9'>" + "".join(f"<th>{h}</th>" for h in COL_HEADERS) + "</tr>",
            ]

            for i in range(count):
                item = root.child(i)
                bg = "#ffffff" if i % 2 == 0 else "#f8fafc"
                parts.append(f"<tr bgcolor='{bg}'>")
                for c in range(item.columnCount()):
                    parts.append(f"<td>{html.escape(item.text(c))}</td>")
                parts.append("</tr>")

            parts.append("</table>")
            parts.append(f"<p><small>{APP_COMPANY} — Sviluppatore: {APP_DEVELOPER} ({WEBSITE_URL})</small></p>")

            doc = QTextEdit()
            doc.setHtml("".join(parts))
            doc.print_(printer)
            self.lbl_status_msg.setText("Report inviato alla stampante.")

    # --- UPDATER ---

    def check_for_updates(self, manual: bool = False) -> None:
        if self.update_checker and self.update_checker.isRunning():
            return

        if manual:
            self.lbl_status_msg.setText("Verifica aggiornamenti su GitHub in corso...")

        self.update_checker = UpdateCheckerThread(APP_VERSION, self)
        self.update_checker.update_found.connect(self._on_update_found)
        self.update_checker.no_update_found.connect(
            lambda ver: self._on_no_update(ver, manual)
        )
        self.update_checker.check_failed.connect(
            lambda err: self._on_update_failed(err, manual)
        )
        self.update_checker.start()

    def _on_update_found(self, tag_version: str, download_url: str, release_notes: str, asset: object) -> None:
        self.lbl_status_msg.setText(f"Nuova versione disponibile: {tag_version}")
        _exec_dialog(UpdateDialog(tag_version, download_url, release_notes, asset or None, self))

    def _on_no_update(self, current_ver: str, manual: bool) -> None:
        self.lbl_status_msg.setText(f"{APP_NAME} v{current_ver} è aggiornato all'ultima versione.")
        if manual:
            QMessageBox.information(
                self,
                "Aggiornamenti",
                f"Stai già utilizzando l'ultima versione disponibile ({APP_NAME} v{current_ver}).",
            )

    def _on_update_failed(self, error_msg: str, manual: bool) -> None:
        self.lbl_status_msg.setText("Verifica aggiornamenti fallita (offline o API limit).")
        if manual:
            QMessageBox.warning(
                self,
                "Verifica Aggiornamenti",
                f"Impossibile verificare gli aggiornamenti su GitHub:\n{error_msg}",
            )

    # --- THEME QSS STYLESHEETS ---

    def _apply_theme(self) -> None:
        theme = self._get_effective_theme()

        if theme == "dark":
            c = {
                "window_bg": "#0f172a",
                "menubar_bg": "#1e293b",
                "menubar_fg": "#f8fafc",
                "menubar_border": "#334155",
                "menubar_item_sel": "#334155",
                "menubar_item_sel_fg": "#38bdf8",
                "menu_bg": "#1e293b",
                "menu_fg": "#f8fafc",
                "menu_border": "#475569",
                "menu_sel_bg": "#2563eb",
                "menu_sel_fg": "#ffffff",
                "menu_sep": "#334155",
                "topbar_bg": "#1e293b",
                "topbar_border": "#334155",
                "brand_title": "#f8fafc",
                "chip_bg": "#0369a1",
                "chip_fg": "#e0f2fe",
                "chip_border": "#0284c7",
                "separator": "#334155",
                "btn_primary_bg": "#2563eb",
                "btn_primary_fg": "#ffffff",
                "btn_primary_hover": "#1d4ed8",
                "btn_sec_bg": "#334155",
                "btn_sec_fg": "#f8fafc",
                "btn_sec_border": "#475569",
                "btn_sec_hover_bg": "#475569",
                "btn_sec_hover_fg": "#ffffff",
                "theme_btn_bg": "#334155",
                "theme_btn_fg": "#f8fafc",
                "theme_btn_border": "#475569",
                "theme_btn_hover_bg": "#475569",
                "author_bg": "#1e293b",
                "author_fg": "#94a3b8",
                "author_border": "#334155",
                "btn_ctrl_bg": "#334155",
                "btn_ctrl_fg": "#f8fafc",
                "btn_ctrl_border": "#475569",
                "btn_ctrl_hover_bg": "#2563eb",
                "btn_ctrl_hover_fg": "#ffffff",
                "card_bg": "#1e293b",
                "card_border": "#334155",
                "editor_bg": "#0f172a",
                "editor_fg": "#f8fafc",
                "editor_border": "#334155",
                "table_header_bg": "#1e293b",
                "table_header_fg": "#38bdf8",
                "table_item_sel_bg": "#2563eb",
                "table_item_sel_fg": "#ffffff",
                "table_alt_bg": "#1e293b",
                "footer_bg": "#1e293b",
                "footer_border": "#334155",
                "footer_status": "#38bdf8",
                "footer_credits": "#94a3b8",
            }
        else:
            c = {
                "window_bg": "#f8fafc",
                "menubar_bg": "#ffffff",
                "menubar_fg": "#0f172a",
                "menubar_border": "#e2e8f0",
                "menubar_item_sel": "#f1f5f9",
                "menubar_item_sel_fg": "#0284c7",
                "menu_bg": "#ffffff",
                "menu_fg": "#0f172a",
                "menu_border": "#cbd5e1",
                "menu_sel_bg": "#2563eb",
                "menu_sel_fg": "#ffffff",
                "menu_sep": "#e2e8f0",
                "topbar_bg": "#ffffff",
                "topbar_border": "#cbd5e1",
                "brand_title": "#0f172a",
                "chip_bg": "#e0f2fe",
                "chip_fg": "#0369a1",
                "chip_border": "#bae6fd",
                "separator": "#cbd5e1",
                "btn_primary_bg": "#2563eb",
                "btn_primary_fg": "#ffffff",
                "btn_primary_hover": "#1d4ed8",
                "btn_sec_bg": "#ffffff",
                "btn_sec_fg": "#0f172a",
                "btn_sec_border": "#cbd5e1",
                "btn_sec_hover_bg": "#f1f5f9",
                "btn_sec_hover_fg": "#0f172a",
                "theme_btn_bg": "#f1f5f9",
                "theme_btn_fg": "#1e293b",
                "theme_btn_border": "#cbd5e1",
                "theme_btn_hover_bg": "#e2e8f0",
                "author_bg": "#ffffff",
                "author_fg": "#64748b",
                "author_border": "#cbd5e1",
                "btn_ctrl_bg": "#f1f5f9",
                "btn_ctrl_fg": "#334155",
                "btn_ctrl_border": "#cbd5e1",
                "btn_ctrl_hover_bg": "#2563eb",
                "btn_ctrl_hover_fg": "#ffffff",
                "card_bg": "#ffffff",
                "card_border": "#cbd5e1",
                "editor_bg": "#ffffff",
                "editor_fg": "#0f172a",
                "editor_border": "#cbd5e1",
                "table_header_bg": "#f1f5f9",
                "table_header_fg": "#0284c7",
                "table_item_sel_bg": "#2563eb",
                "table_item_sel_fg": "#ffffff",
                "table_alt_bg": "#f8fafc",
                "footer_bg": "#f1f5f9",
                "footer_border": "#cbd5e1",
                "footer_status": "#0284c7",
                "footer_credits": "#64748b",
            }

        qss = f"""
            QMainWindow {{
                background-color: {c['window_bg']};
            }}
            
            QMenuBar {{
                background-color: {c['menubar_bg']};
                color: {c['menubar_fg']};
                font-size: 13px;
                font-family: 'Segoe UI', system-ui, sans-serif;
                border-bottom: 1px solid {c['menubar_border']};
                padding: 2px 6px;
            }}
            QMenuBar::item {{
                background-color: transparent;
                padding: 6px 12px;
                border-radius: 6px;
            }}
            QMenuBar::item:selected {{
                background-color: {c['menubar_item_sel']};
                color: {c['menubar_item_sel_fg']};
            }}
            
            QMenu {{
                background-color: {c['menu_bg']};
                color: {c['menu_fg']};
                border: 1px solid {c['menu_border']};
                border-radius: 10px;
                padding: 6px;
                font-size: 13px;
            }}
            QMenu::item {{
                padding: 6px 20px;
                border-radius: 6px;
            }}
            QMenu::item:selected {{
                background-color: {c['menu_sel_bg']};
                color: {c['menu_sel_fg']};
            }}
            QMenu::separator {{
                height: 1px;
                background-color: {c['menu_sep']};
                margin: 4px 6px;
            }}

            #TopBar {{
                background-color: {c['topbar_bg']};
                border: 1px solid {c['topbar_border']};
                border-radius: 14px;
            }}
            #BrandTitle {{
                color: {c['brand_title']};
                font-size: 16px;
                font-weight: 800;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }}
            #M3VersionChip {{
                background-color: {c['chip_bg']};
                color: {c['chip_fg']};
                border: 1px solid {c['chip_border']};
                border-radius: 9px;
                padding: 2px 8px;
                font-size: 10px;
                font-weight: 700;
            }}
            #VerticalSeparator {{
                color: {c['separator']};
                margin: 4px 0px;
            }}
            #HorizontalSeparator {{
                color: {c['separator']};
                margin: 4px 0px;
            }}

            #PrimaryBtn {{
                background: {c['btn_primary_bg']};
                color: {c['btn_primary_fg']};
                border: none;
                border-radius: 14px;
                padding: 6px 16px;
                font-weight: 700;
                font-size: 13px;
            }}
            #PrimaryBtn:hover {{
                background: {c['btn_primary_hover']};
            }}

            #SecondaryBtn {{
                background-color: {c['btn_sec_bg']};
                color: {c['btn_sec_fg']};
                border: 1px solid {c['btn_sec_border']};
                border-radius: 14px;
                padding: 6px 14px;
                font-size: 12px;
                font-weight: 600;
            }}
            #SecondaryBtn:hover {{
                background-color: {c['btn_sec_hover_bg']};
                color: {c['btn_sec_hover_fg']};
            }}

            #ThemeToolBtn {{
                background-color: {c['theme_btn_bg']};
                color: {c['theme_btn_fg']};
                border: 1px solid {c['theme_btn_border']};
                border-radius: 14px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: 600;
            }}
            #ThemeToolBtn:hover {{
                background-color: {c['theme_btn_hover_bg']};
            }}

            #AuthorBadge {{
                background-color: {c['author_bg']};
                color: {c['author_fg']};
                border: 1px solid {c['author_border']};
                border-radius: 12px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 600;
            }}

            #ControlBtn {{
                background-color: {c['btn_ctrl_bg']};
                color: {c['btn_ctrl_fg']};
                border: 1px solid {c['btn_ctrl_border']};
                border-radius: 10px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 600;
            }}
            #ControlBtn:hover {{
                background-color: {c['btn_ctrl_hover_bg']};
                color: {c['btn_ctrl_hover_fg']};
                border-color: {c['btn_ctrl_hover_bg']};
            }}

            #InfoCard {{
                background-color: {c['card_bg']};
                border: 1px solid {c['card_border']};
                border-radius: 14px;
            }}

            QComboBox, QLineEdit {{
                background-color: {c['editor_bg']};
                color: {c['editor_fg']};
                border: 1px solid {c['card_border']};
                border-radius: 8px;
                padding: 4px 8px;
                selection-background-color: {c['table_item_sel_bg']};
            }}

            QProgressBar {{
                border: none;
                background-color: {c['editor_bg']};
                border-radius: 6px;
            }}
            QProgressBar::chunk {{
                background-color: {c['btn_primary_bg']};
                border-radius: 6px;
            }}

            QTreeWidget {{
                background-color: {c['editor_bg']};
                color: {c['editor_fg']};
                border: 1px solid {c['card_border']};
                border-radius: 10px;
                font-size: 12px;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }}
            QTreeWidget::item {{
                padding: 4px;
            }}
            QTreeWidget::item:alternate {{
                background-color: {c['table_alt_bg']};
            }}
            QTreeWidget::item:selected {{
                background-color: {c['table_item_sel_bg']};
                color: {c['table_item_sel_fg']};
                border-radius: 4px;
            }}
            QHeaderView::section {{
                background-color: {c['table_header_bg']};
                color: {c['table_header_fg']};
                font-weight: 700;
                font-size: 12px;
                border: none;
                border-bottom: 1px solid {c['card_border']};
                padding: 6px 8px;
            }}

            QTextEdit {{
                background-color: {c['editor_bg']};
                color: {c['editor_fg']};
                border: 1px solid {c['card_border']};
                border-radius: 10px;
            }}

            #FooterBar {{
                background-color: {c['footer_bg']};
                border-top: 1px solid {c['footer_border']};
                border-radius: 0px;
            }}
            #FooterStatus {{
                color: {c['footer_status']};
                font-size: 11px;
                font-weight: 700;
            }}
            #FooterCredits {{
                color: {c['footer_credits']};
                font-size: 10px;
            }}
        """
        self.setStyleSheet(qss)


def main() -> None:
    if sys.platform != "win32":
        print("LanScanner è progettato principalmente per sistemi Windows.")

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_COMPANY)

    window = LanScannerWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
