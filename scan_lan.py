# -*- coding: utf-8 -*-
"""
LanScanner — Network Scanner Portatile per Windows.
Design Material 3 con PySide6 (Qt 6).
Autore: Vincenzo Curia (vcuria.app) — NGV Group S.R.L.
"""

from __future__ import annotations

import concurrent.futures
import csv
import ipaddress
import json
import os
import pathlib
import re
import socket
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
    QRect,
    QSettings,
    QSignalBlocker,
    QSize,
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
    QClipboard,
    QColor,
    QCursor,
    QDesktopServices,
    QFont,
    QIcon,
    QKeySequence,
    QPainter,
    QPixmap,
)
from PySide6.QtPrintSupport import QPrintDialog, QPrinter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "LanScanner"
APP_VERSION = "1.2.0"
APP_COMPANY = "NGV Group S.R.L."
APP_DEVELOPER = "Vincenzo Curia"
GITHUB_REPO = "vincenzocuria/LanScannerPortable"
WEBSITE_URL = "https://vcuria.app"

COLS = ("ip", "ping", "mac", "vendor", "host", "hint")
COL_HEADERS = ["IP", "Stato Ping / Rilevamento", "MAC", "Vendor (OUI)", "Hostname", "Indizio Dispositivo"]
COL_WIDTHS = [130, 160, 140, 210, 210, 150]

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
                        if len(oui) == 6:
                            m[oui] = name.strip()
                except Exception:
                    m = {}
            _OUI_MAP = m
        return _OUI_MAP


def _vendor_from_mac(mac: str) -> str:
    if not mac or mac == "—":
        return ""
    m = mac.upper().replace("-", ":").replace(" ", "")
    parts = [p for p in m.split(":") if p]
    if len(parts) < 3:
        return ""
    return _load_oui_map().get("".join(parts[:3]), "")


def _quick_hint(hostname: str, vendor: str, mac: str) -> str:
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    if h in ("", "—", "..."):
        h = ""
    hints: List[str] = []
    if "vmware" in v or "virtualbox" in v or "pcs systemtechnik" in v:
        hints.append("VM")
    if "raspberry" in v or "espressif" in v:
        hints.append("SBC/IoT")
    if "apple" in v or "iphone" in h or "ipad" in h:
        hints.append("Apple?")
    if "samsung" in v or "xiaomi" in v or "oneplus" in v:
        hints.append("Mobile/TV?")
    if "amazon" in v or "ech" in h:
        hints.append("Amazon/IoT?")
    if "philips" in v or "hue" in h:
        hints.append("Hue/IoT?")
    if h.startswith("desk") or "win-" in h or "desktop-" in h:
        hints.append("PC Windows?")
    if "android" in h:
        hints.append("Android?")
    if "chromecast" in h or "gw-" in h:
        hints.append("Google Cast?")
    if "printer" in h or "print" in h:
        hints.append("Stampante?")
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


def _get_network_interfaces() -> List[Tuple[str, str]]:
    """Restituisce l'elenco delle schede di rete attive sul sistema (Nome, IP)."""
    interfaces: List[Tuple[str, str]] = []
    try:
        cr = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="replace",
            creationflags=cr,
            timeout=5,
        )
        current_adapter = "Scheda di rete"
        for line in (r.stdout or "").splitlines():
            line_str = line.strip()
            if line.startswith("Scheda ") or "adapter" in line.lower():
                current_adapter = line.split(":")[0].strip()
            elif "IPv4" in line_str or "Indirizzo IPv4" in line_str:
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line_str)
                if m:
                    ip = m.group(1)
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        interfaces.append((current_adapter, ip))
    except Exception:
        pass

    if not interfaces:
        local_ip = _local_ipv4()
        if local_ip:
            interfaces.append(("Scheda Predefinita", local_ip))
    return interfaces


def _default_range_for_ip(ip: str) -> Tuple[str, str]:
    if not ip or len(ip.split(".")) != 4:
        return "192.168.1.1", "192.168.1.254"
    b = ".".join(ip.split(".")[:3])
    return f"{b}.1", f"{b}.254"


def _default_range() -> Tuple[str, str]:
    return _default_range_for_ip(_local_ipv4() or "")


def _iter_ipv4(start: str, end: str) -> List[str]:
    a, b = ipaddress.IPv4Address(start.strip()), ipaddress.IPv4Address(end.strip())
    if int(a) > int(b):
        a, b = b, a
    return [str(ipaddress.IPv4Address(i)) for i in range(int(a), int(b) + 1)]


def _ping_one(ip: str, timeout_ms: int) -> Tuple[bool, float]:
    """Effettua un ping ICMP e restituisce (successo, tempo_rtt_ms)."""
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
            # Cerca il valore preciso di tempo RTT se presente nell'output
            m = re.search(r"(?:durata|tempo|time)[=<](\d+)ms", out, re.IGNORECASE)
            if m:
                return True, float(m.group(1))
            return True, round(elapsed_ms, 1)
        return False, 0.0
    except (OSError, subprocess.TimeoutExpired):
        return False, 0.0


_ARP_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")


def _arp_map() -> Dict[str, str]:
    try:
        cr = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=cr,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    m: Dict[str, str] = {}
    for line in (r.stdout or "").splitlines():
        for x in _ARP_REGEX.finditer(line):
            ip_s, md = x.group(1), x.group(2).upper()
            m[ip_s] = md.replace("-", ":")
    return m


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


def _nbtstat(ip: str) -> str:
    try:
        cr = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="replace",
            creationflags=cr,
            timeout=20,
        )
        return (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return "(nbtstat non disponibile o timeout)"


def _probe_ports(ip: str, ports: List[Tuple[int, str]], timeout: float = 0.35) -> List[str]:
    out = []
    for port, label in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                out.append(f"{port} ({label})")
        except OSError:
            pass
        finally:
            s.close()
    return out


# --- BACKGROUND THREADS ---

class UpdateCheckerThread(QThread):
    update_found = Signal(str, str, str)     # tag_version, download_url, release_notes
    no_update_found = Signal(str)            # current_version
    check_failed = Signal(str)               # error_message

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
                        self.update_found.emit(tag_name, html_url, notes)
                    else:
                        self.no_update_found.emit(self.current_version)
                    return
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.no_update_found.emit(self.current_version)
                return
            self.check_failed.emit(f"HTTP Error {e.code}")
            return
        except Exception:
            try:
                tags_url = f"https://api.github.com/repos/{GITHUB_REPO}/tags"
                req = urllib.request.Request(tags_url, headers=headers)
                with urllib.request.urlopen(req, timeout=6) as response:
                    if response.status == 200:
                        tags = json.loads(response.read().decode("utf-8"))
                        if tags and isinstance(tags, list):
                            tag_name = tags[0].get("name", "").strip()
                            latest_ver = tag_name.lstrip("v")
                            html_url = f"https://github.com/{GITHUB_REPO}/releases"
                            if self._is_newer(latest_ver, self.current_version):
                                self.update_found.emit(tag_name, html_url, "")
                                return
                            else:
                                self.no_update_found.emit(self.current_version)
                                return
            except Exception as ex:
                self.check_failed.emit(str(ex))
                return

            self.no_update_found.emit(self.current_version)
            return

    @staticmethod
    def _is_newer(latest_str: str, current_str: str) -> bool:
        def parse_version(v: str) -> List[int]:
            parts = re.findall(r"\d+", v)
            return [int(p) for p in parts] if parts else [0]

        return parse_version(latest_str) > parse_version(current_str)


class ContinuousPingWorker(QThread):
    ping_result = Signal(bool, float, str)  # success, rtt_ms, timestamp_str

    def __init__(self, ip: str, interval_sec: float = 1.0, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.interval_sec = interval_sec
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        while self._running:
            ok, rtt = _ping_one(self.ip, timeout_ms=800)
            now_str = time.strftime("%H:%M:%S")
            self.ping_result.emit(ok, rtt, now_str)
            time.sleep(self.interval_sec)


class ScanWorkerThread(QThread):
    progress_updated = Signal(int, int)       # done, total
    initial_alive_found = Signal(list)        # list of alive tuples (ip, status_str, mac, vendor, "...", hint)
    hostname_resolved = Signal(str, str, str) # ip, hostname, hint
    scan_finished = Signal(int)              # total_alive_count
    scan_interrupted = Signal()
    scan_error = Signal(str)

    def __init__(self, hosts: List[str], max_workers: int = 48, parent=None):
        super().__init__(parent)
        self.hosts = hosts
        self.max_workers = max_workers
        self._cancel_event = threading.Event()

    def stop(self) -> None:
        self._cancel_event.set()

    def run(self) -> None:
        timeout_ms = 750
        ping_results: Dict[str, Tuple[bool, float]] = {}
        done = 0
        total = len(self.hosts)

        try:
            _load_oui_map()

            # 1. Rileva subito la tabella ARP esistente di sistema
            initial_arp = _arp_map()

            # 2. Esegui la scansione ICMP Ping parallela
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futs = {ex.submit(_ping_one, ip, timeout_ms): ip for ip in self.hosts}
                for fu in concurrent.futures.as_completed(futs):
                    if self._cancel_event.is_set():
                        break
                    ip = futs[fu]
                    try:
                        ok, rtt = fu.result()
                    except Exception:
                        ok, rtt = False, 0.0
                    ping_results[ip] = (ok, rtt)
                    done += 1
                    if done % 8 == 0 or done == total:
                        self.progress_updated.emit(done, total)

            if self._cancel_event.is_set():
                self.scan_interrupted.emit()
                return

            # 3. Aggiorna la tabella ARP post-ping per identificare tutti gli host attivi (anche quelli con ICMP bloccato!)
            time.sleep(0.3)
            post_arp = _arp_map()
            combined_arp = {**initial_arp, **post_arp}

            rows: List[Tuple[str, str, str, str, str, str]] = []
            alive_ips: List[str] = []

            for ip in self.hosts:
                ok, rtt = ping_results.get(ip, (False, 0.0))
                mac = combined_arp.get(ip, "")

                if ok:
                    alive_ips.append(ip)
                    status_str = f"🟢 Attivo ({int(rtt)} ms)" if rtt > 0 else "🟢 Attivo"
                    v = _vendor_from_mac(mac) if mac else ""
                    rows.append((ip, status_str, mac or "—", v or "—", "...", "—"))
                elif mac and mac != "—":
                    # Dispositivo presente nella tabella ARP ma che blocca il Ping ICMP (es. firewall attivo)
                    alive_ips.append(ip)
                    status_str = "🟡 Risponde ARP (Firewall)"
                    v = _vendor_from_mac(mac)
                    rows.append((ip, status_str, mac, v or "—", "...", "—"))

            sorted_rows = sorted(rows, key=lambda x: int(ipaddress.IPv4Address(x[0])))
            self.initial_alive_found.emit(sorted_rows)

            # 4. Risoluzione Hostname e Hint in background
            sorted_ips = [r[0] for r in sorted_rows]
            for ip in sorted_ips:
                if self._cancel_event.is_set():
                    break
                mac = combined_arp.get(ip, "")
                v = _vendor_from_mac(mac) if mac else ""
                hn = _resolve_hostname(ip) or "—"
                hint = _quick_hint(hn, v, mac)
                self.hostname_resolved.emit(ip, hn, hint)

            if self._cancel_event.is_set():
                self.scan_interrupted.emit()
                return

            self.scan_finished.emit(len(sorted_rows))

        except Exception as e:
            self.scan_error.emit(str(e))


# --- DIALOGS & TOOLS ---

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

        # Header Cards
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

        # Log Text Box
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(QFont("Consolas", 9.5))
        layout.addWidget(self.txt_log)

        # Actions Row
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

        # Worker launch
        self.worker = ContinuousPingWorker(target_ip, interval_sec=1.0, parent=self)
        self.worker.ping_result.connect(self._on_ping_result)
        self.worker.start()

    def _on_ping_result(self, ok: bool, rtt: float, now_str: str) -> None:
        self.sent_count += 1
        if ok:
            self.recv_count += 1
            self.rtt_list.append(rtt)
            rtt_str = f"{int(rtt)} ms" if rtt > 0 else "<1 ms"
            self.txt_log.append(f"[{now_str}] Risposta da {self.target_ip}: tempo={rtt_str}")
        else:
            self.txt_log.append(f"[{now_str}] Richiesta scaduta per {self.target_ip} (Timeout)")

        # Update stats
        loss_pct = round(((self.sent_count - self.recv_count) / self.sent_count) * 100, 1)
        avg_rtt = round(sum(self.rtt_list) / len(self.rtt_list), 1) if self.rtt_list else 0.0

        self.card_sent.setText(f"Inviati: <b>{self.sent_count}</b>")
        self.card_recv.setText(f"Ricevuti: <b>{self.recv_count}</b>")
        self.card_loss.setText(f"Persi: <b>{loss_pct}%</b>")
        self.card_rtt.setText(f"Latenza Media: <b>{avg_rtt} ms</b>" if self.rtt_list else "Latenza: -")

    def _toggle_ping(self) -> None:
        if self.worker.isRunning():
            self.worker.stop()
            self.btn_toggle.setText("▶️ Riprendi")
        else:
            self.worker = ContinuousPingWorker(self.target_ip, interval_sec=1.0, parent=self)
            self.worker.ping_result.connect(self._on_ping_result)
            self.worker.start()
            self.btn_toggle.setText("⏸️ Pausa")

    def _copy_log(self) -> None:
        QApplication.clipboard().setText(self.txt_log.toPlainText())
        QMessageBox.information(self, "Copia", "Log dei ping copiato negli appunti.")

    def closeEvent(self, event) -> None:
        if self.worker.isRunning():
            self.worker.stop()
        super().closeEvent(event)


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Informazioni su {APP_NAME}")
        self.setFixedSize(500, 420)
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
            "<b>Licenza & Note:</b><br>"
            "Software gratuito distribuito ad uso libero per fini personali e commerciali, "
            "senza alcuna garanzia e senza obbligo di assistenza.<br><br>"
            "L'utente è unico responsabile dell'impiego conforme alle norme vigenti "
            "e di operare esclusivamente su reti per le quali dispone di preventiva autorizzazione.<br><br>"
            "<small><i>Database IEEE OUI derivato dal file manuf del progetto Wireshark.</i></small>"
        )

        lbl_body = QLabel(body_text)
        lbl_body.setWordWrap(True)
        lbl_body.setOpenExternalLinks(True)
        lbl_body.setFont(QFont("Segoe UI", 10))
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
    def __init__(self, tag_version: str, download_url: str, release_notes: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Aggiornamento Disponibile")
        self.setFixedSize(520, 380)
        _set_window_icon(self)
        self.download_url = download_url

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

        btn_box = QHBoxLayout()
        btn_download = QPushButton("🌐 Scarica Aggiornamento su GitHub")
        btn_download.setObjectName("PrimaryBtn")
        btn_download.setCursor(Qt.PointingHandCursor)
        btn_download.clicked.connect(self._open_download)

        btn_close = QPushButton("Chiudi")
        btn_close.setObjectName("SecondaryBtn")
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.reject)

        btn_box.addWidget(btn_download)
        btn_box.addStretch()
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)

    def _open_download(self) -> None:
        QDesktopServices.openUrl(QUrl(self.download_url))
        self.accept()


class DeviceDetailDialog(QDialog):
    PORTS = [
        (80, "HTTP Web"),
        (443, "HTTPS Web Sec"),
        (445, "SMB File Share"),
        (22, "SSH Terminal"),
        (21, "FTP File Transfer"),
        (23, "Telnet"),
        (53, "DNS Name Server"),
        (3389, "RDP Remote Desktop"),
        (554, "RTSP Camera"),
        (9100, "JetDirect Stampa"),
        (5000, "UPnP / Synology"),
        (8080, "HTTP Alt"),
    ]

    def __init__(self, ip: str, row_values: Tuple[str, ...], parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Dettaglio Dispositivo — {ip}")
        self.resize(640, 500)
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
            grid.addWidget(l, row, col * 2)
            grid.addWidget(v, row, col * 2 + 1)

        add_info("Indirizzo IP", row_values[0] if len(row_values) > 0 else ip, 0, 0)
        add_info("Stato Ping", row_values[1] if len(row_values) > 1 else "-", 0, 1)
        add_info("Indirizzo MAC", row_values[2] if len(row_values) > 2 else "-", 1, 0)
        add_info("Vendor OUI", row_values[3] if len(row_values) > 3 else "-", 1, 1)
        add_info("Hostname", row_values[4] if len(row_values) > 4 else "-", 2, 0)
        add_info("Indizio", row_values[5] if len(row_values) > 5 else "-", 2, 1)

        layout.addLayout(grid)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setObjectName("HorizontalSeparator")
        layout.addWidget(sep)

        lbl_report = QLabel("📜 Report di Analisi Avanzata (NetBIOS + Porte TCP):")
        lbl_report.setFont(QFont("Segoe UI", 10, QFont.Bold))
        layout.addWidget(lbl_report)

        self.txt_report = QTextEdit()
        self.txt_report.setReadOnly(True)
        self.txt_report.setFont(QFont("Consolas", 9.5))
        layout.addWidget(self.txt_report)

        btn_box = QHBoxLayout()
        btn_analyze = QPushButton("🔍 Analizza (NetBIOS + Porte)")
        btn_analyze.setObjectName("PrimaryBtn")
        btn_analyze.setCursor(Qt.PointingHandCursor)
        btn_analyze.clicked.connect(self._start_analysis)

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

        self.txt_report.setText("Clicca su 'Analizza' per eseguire l'analisi NetBIOS e la scansione delle porte TCP principali.")

    def _start_analysis(self) -> None:
        self.txt_report.setText("Analisi avanzata in corso...\nAttendere qualche secondo...")

        def job() -> None:
            lines = [f"=== REPORT DETTAGLIATO DISPOSITIVO {self._ip} ===\n\n"]
            hn = _resolve_hostname(self._ip)
            lines.append(f"Hostname (DNS Reverse): {hn or '—'}\n\n")
            lines.append("=== NetBIOS Name Service (nbtstat -A) ===\n")
            lines.append(_nbtstat(self._ip) + "\n\n")
            lines.append("=== Sondaggio Porte TCP Comuni ===\n")
            openp = _probe_ports(self._ip, self.PORTS)
            lines.append(
                ", ".join(openp) if openp else "Nessuna delle porte standard testate risponde in apertura.\n"
            )
            lines.append("\n=== Nota ===\n")
            lines.append("Vendor identificato tramite OUI IEEE. Eventuali firewall locali o di rete possono filtrare le risposte alle porte.\n")
            report = "".join(lines)
            QTimer.singleShot(0, lambda: self.txt_report.setText(report))

        threading.Thread(target=job, daemon=True).start()

    def _copy_report(self) -> None:
        cb = QApplication.clipboard()
        cb.setText(self.txt_report.toPlainText())
        QMessageBox.information(self, "Copia", "Report di dettaglio copiato negli appunti.")


# --- MAIN APPLICATION WINDOW ---

class LanScannerWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} — Material 3 Edition")
        self.resize(1180, 700)
        self.setMinimumSize(880, 520)

        _set_window_icon(self)

        self.settings = QSettings("NGVGroup", "LanScanner")
        self.theme_mode = self.settings.value("theme_mode", "auto")
        self.scan_worker: Optional[ScanWorkerThread] = None
        self.update_checker: Optional[UpdateCheckerThread] = None

        self._create_menu_bar()
        self._init_ui()
        self._apply_theme()
        self._update_recent_menu()
        self._populate_network_adapters()

        QTimer.singleShot(2500, lambda: self.check_for_updates(manual=False))

    # --- THEME ENGINE ---
    def _get_effective_theme(self) -> str:
        if self.theme_mode == "light":
            return "light"
        elif self.theme_mode == "dark":
            return "dark"
        else:  # "auto"
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

        self.act_export = QAction("💾 Esporta Risultati CSV...", self)
        self.act_export.setShortcut(QKeySequence.Save)
        self.act_export.triggered.connect(self._export_csv_dialog)
        menu_file.addAction(self.act_export)

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

        act_copy = QAction("📋 Copia Righe Selezionate", self)
        act_copy.setShortcut(QKeySequence.Copy)
        act_copy.triggered.connect(self._copy_selection)
        menu_tools.addAction(act_copy)

        act_ping_cont = QAction("📈 Ping Continuo & Latenza...", self)
        act_ping_cont.triggered.connect(self._open_continuous_ping_selected)
        menu_tools.addAction(act_ping_cont)

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
        act_info.triggered.connect(lambda: AboutDialog(self).exec())
        menu_help.addAction(act_info)

        act_legal = QAction("⚖️ Avviso di Responsabilità Legale", self)
        act_legal.triggered.connect(lambda: LegalDisclaimerDialog(self).exec())
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

        # Quick Theme Dropdown
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

        lbl_s = QLabel("IP Iniziale:")
        lbl_s.setFont(QFont("Segoe UI", 9.5, QFont.Bold))
        self.txt_ip_start = QLineEdit()
        self.txt_ip_start.setFixedWidth(120)
        self.txt_ip_start.setFont(QFont("Consolas", 10))

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

        row_inputs.addWidget(lbl_adapter)
        row_inputs.addWidget(self.cmb_adapters)
        row_inputs.addWidget(lbl_s)
        row_inputs.addWidget(self.txt_ip_start)
        row_inputs.addWidget(lbl_e)
        row_inputs.addWidget(self.txt_ip_end)
        row_inputs.addWidget(btn_auto_sub)

        row_inputs.addSpacing(10)

        # Search filter in table
        lbl_filter = QLabel("🔎 Filtra:")
        lbl_filter.setFont(QFont("Segoe UI", 9.5))
        self.txt_filter = QLineEdit()
        self.txt_filter.setPlaceholderText("Cerca IP, MAC, Hostname...")
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

        self.lbl_status_msg = QLabel("Pronto — Inserisci un intervallo IP ed avvia la scansione")
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
        self.cmb_adapters.blockSignals(True)
        self.cmb_adapters.clear()
        for name, ip in adapters:
            self.cmb_adapters.addItem(f"{name} ({ip})", userData=ip)
        self.cmb_adapters.blockSignals(False)

    def _on_adapter_selected(self, index: int) -> None:
        ip = self.cmb_adapters.itemData(index)
        if ip:
            s_a, s_b = _default_range_for_ip(ip)
            self.txt_ip_start.setText(s_a)
            self.txt_ip_end.setText(s_b)
            self.lbl_status_msg.setText(f"Selezionata scheda: {ip} → Intervallo: {s_a} - {s_b}")

    # --- SCAN LOGIC & WORKER ---

    def _set_local_subnet(self) -> None:
        a, b = _default_range()
        self.txt_ip_start.setText(a)
        self.txt_ip_end.setText(b)
        self.lbl_status_msg.setText(f"Rilevata subnet locale: {a} - {b}")

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
            ipaddress.IPv4Address(s0)
            ipaddress.IPv4Address(s1)
        except ValueError:
            QMessageBox.critical(self, "Errore", "Indirizzi IPv4 non validi.")
            return

        try:
            hosts = _iter_ipv4(s0, s1)
        except Exception as e:
            QMessageBox.critical(self, "Errore", f"Impossibile generare l'intervallo IP: {e}")
            return

        if len(hosts) > 4096:
            QMessageBox.critical(self, "Errore", "L'intervallo massimo consentito è di 4096 indirizzi IP.")
            return

        self.add_recent_range(s0, s1)
        self.table.clear()
        self.prog_bar.setMaximum(len(hosts))
        self.prog_bar.setValue(0)

        self.btn_scan.setText("🛑 Interrompi")
        self.btn_scan.setEnabled(True)
        self.lbl_status_msg.setText(f"Scansione in corso su {len(hosts)} host IPv4 (Ping ICMP + ARP Cache)...")

        self.scan_worker = ScanWorkerThread(hosts, max_workers=48)
        self.scan_worker.progress_updated.connect(self._on_scan_progress)
        self.scan_worker.initial_alive_found.connect(self._on_initial_alive)
        self.scan_worker.hostname_resolved.connect(self._on_hostname_resolved)
        self.scan_worker.scan_finished.connect(self._on_scan_finished)
        self.scan_worker.scan_interrupted.connect(self._on_scan_interrupted)
        self.scan_worker.scan_error.connect(self._on_scan_error)
        self.scan_worker.start()

    @Slot(int, int)
    def _on_scan_progress(self, done: int, total: int) -> None:
        self.prog_bar.setValue(done)
        self.lbl_status_msg.setText(f"Ping ICMP in corso: {done}/{total} host verificati...")

    @Slot(list)
    def _on_initial_alive(self, rows: List[Tuple[str, str, str, str, str, str]]) -> None:
        for r in rows:
            item = QTreeWidgetItem(self.table, list(r))
            item.setTextAlignment(1, Qt.AlignCenter)

    @Slot(str, str, str)
    def _on_hostname_resolved(self, ip: str, hostname: str, hint: str) -> None:
        root = self.table.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item.text(0) == ip:
                item.setText(4, hostname)
                item.setText(5, hint)
                break

    @Slot(int)
    def _on_scan_finished(self, total_alive: int) -> None:
        self.prog_bar.setValue(self.prog_bar.maximum())
        self.btn_scan.setText("🔍 Scansiona")
        self.btn_scan.setEnabled(True)
        self.lbl_status_msg.setText(f"Scansione completata: trovati {total_alive} host attivi nella LAN.")

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

    # --- FILTERING & CONTEXT MENU ---
    def _apply_filter(self, text: str) -> None:
        query = text.strip().lower()
        root = self.table.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            match = False
            if not query:
                match = True
            else:
                for c in range(item.columnCount()):
                    if query in item.text(c).lower():
                        match = True
                        break
            item.setHidden(not match)

    def _show_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        menu = QMenu(self)

        act_copy = menu.addAction("📋 Copia Selezione")
        act_copy.triggered.connect(self._copy_selection)

        if item:
            ip = item.text(0)
            mac = item.text(2)

            menu.addSeparator()

            act_web = menu.addAction(f"🌐 Apri Interfaccia Web (http://{ip})")
            act_web.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(f"http://{ip}")))

            act_webs = menu.addAction(f"🔒 Apri Interfaccia Web Sicura (https://{ip})")
            act_webs.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(f"https://{ip}")))

            act_rdp = menu.addAction(f"🖥️ Connetti via Desktop Remoto (RDP)")
            act_rdp.triggered.connect(lambda: self._launch_rdp(ip))

            act_smb = menu.addAction(f"📁 Apri Condivisione File (SMB - \\\\{ip})")
            act_smb.triggered.connect(lambda: self._launch_smb(ip))

            if mac and mac != "—":
                act_wol = menu.addAction(f"⚡ Invia Pacchetto Wake-on-LAN (WoL)")
                act_wol.triggered.connect(lambda: self._trigger_wol(mac, ip))

            menu.addSeparator()

            act_ping_cont = menu.addAction(f"📈 Ping Continuo & Monitor Latenza...")
            act_ping_cont.triggered.connect(lambda: ContinuousPingDialog(ip, self).exec())

            act_det = menu.addAction("🔍 Dettaglio Dispositivo & Porte...")
            act_det.triggered.connect(lambda: self._open_detail_item(item))

        menu.addSeparator()

        act_exp_all = menu.addAction("💾 Esporta Tutti i Risultati in CSV")
        act_exp_all.triggered.connect(lambda: self._export_csv_action(only_selected=False))

        act_exp_sel = menu.addAction("💾 Esporta Solo Selezione in CSV")
        act_exp_sel.triggered.connect(lambda: self._export_csv_action(only_selected=True))

        menu.addSeparator()
        act_info = menu.addAction("ℹ️ Informazioni e Crediti")
        act_info.triggered.connect(lambda: AboutDialog(self).exec())

        menu.exec(self.table.mapToGlobal(pos))

    def _launch_rdp(self, ip: str) -> None:
        try:
            subprocess.Popen(["mstsc", f"/v:{ip}"])
            self.lbl_status_msg.setText(f"Avviata connessione Desktop Remoto a {ip}...")
        except Exception as e:
            QMessageBox.critical(self, "RDP", f"Impossibile avviare RDP: {e}")

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
        ContinuousPingDialog(ip, self).exec()

    def _open_detail_item(self, item: QTreeWidgetItem) -> None:
        values = tuple(item.text(i) for i in range(item.columnCount()))
        if values:
            DeviceDetailDialog(values[0], values, self).exec()

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

    # --- CSV EXPORT & PRINTING ---

    def _export_csv_dialog(self) -> None:
        self._export_csv_action(only_selected=False)

    def _export_csv_action(self, only_selected: bool = False) -> None:
        root = self.table.invisibleRootItem()
        items = self.table.selectedItems() if only_selected else [root.child(i) for i in range(root.childCount())]

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

    def _print_report(self) -> None:
        root = self.table.invisibleRootItem()
        count = root.childCount()
        if count == 0:
            QMessageBox.warning(self, "Stampa", "Nessun dato disponibile da stampare.")
            return

        printer = QPrinter(QPrinter.HighResolution)
        dialog = QPrintDialog(printer, self)
        if dialog.exec() == QPrintDialog.Accepted:
            html = [
                f"<h2>{APP_NAME} — Report Scansione LAN</h2>",
                f"<p><b>Data:</b> {time.strftime('%d/%m/%Y %H:%M')} | <b>Host Trovati:</b> {count}</p>",
                "<table border='1' cellspacing='0' cellpadding='5' style='border-collapse:collapse; width:100%; font-family: Segoe UI, sans-serif;'>",
                "tr bgcolor='#f1f5f9'>" + "".join(f"<th>{h}</th>" for h in COL_HEADERS) + "</tr>"
            ]

            for i in range(count):
                item = root.child(i)
                bg = "#ffffff" if i % 2 == 0 else "#f8fafc"
                html.append(f"<tr bgcolor='{bg}'>")
                for c in range(item.columnCount()):
                    html.append(f"<td>{item.text(c)}</td>")
                html.append("</tr>")

            html.append("</table>")
            html.append(f"<p><small>{APP_COMPANY} — Sviluppatore: {APP_DEVELOPER} ({WEBSITE_URL})</small></p>")

            doc = QTextEdit()
            doc.setHtml("".join(html))
            doc.print_(printer)
            self.lbl_status_msg.setText("Report inviato alla stampante.")

    # --- UPDATER ---

    def check_for_updates(self, manual: bool = False) -> None:
        if self.update_checker and self.update_checker.isRunning():
            return

        if manual:
            self.lbl_status_msg.setText("Verifica aggiornamenti su GitHub in corso...")

        self.update_checker = UpdateCheckerThread(APP_VERSION, self)
        self.update_checker.update_found.connect(
            lambda tag, url, notes: self._on_update_found(tag, url, notes)
        )
        self.update_checker.no_update_found.connect(
            lambda ver: self._on_no_update(ver, manual)
        )
        self.update_checker.check_failed.connect(
            lambda err: self._on_update_failed(err, manual)
        )
        self.update_checker.start()

    def _on_update_found(self, tag_version: str, download_url: str, release_notes: str) -> None:
        self.lbl_status_msg.setText(f"Nuova versione disponibile: {tag_version}")
        UpdateDialog(tag_version, download_url, release_notes, self).exec()

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
        else:  # light
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
        print("LanScanner è progettato esclusivamente per sistemi Windows.")

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_COMPANY)

    window = LanScannerWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
