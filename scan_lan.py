# -*- coding: utf-8 -*-
# Scanner LAN Windows. OUI: oui_vendor.zlib (manuf Wireshark).
# Build: pyinstaller --onefile --windowed --icon app_icon.ico --add-data "oui_vendor.zlib;." --add-data "app_icon.ico;." scan_lan.py
from __future__ import annotations

import concurrent.futures
import csv
import ipaddress
import pathlib
import re
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import zlib

APP_NAME = "LanScanner"
APP_VERSION = "1.1.0"
APP_COMPANY = "NGV Group S.R.L"
APP_DEVELOPER = "Vincenzo Curia"

COLS = ("ip", "ping", "mac", "vendor", "host", "hint")
_OUI_LOCK = threading.Lock()
_OUI_MAP: dict[str, str] | None = None


def _resource_dir() -> pathlib.Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return pathlib.Path(sys._MEIPASS)
    return pathlib.Path(__file__).resolve().parent


def _set_window_icon(w: tk.Tk | tk.Toplevel) -> None:
    path = _resource_dir() / "app_icon.ico"
    if path.is_file():
        try:
            w.iconbitmap(str(path))
        except tk.TclError:
            pass


def _apply_style(root: tk.Misc) -> ttk.Style:
    s = ttk.Style(root)
    try:
        s.theme_use("clam")
    except tk.TclError:
        pass
    bg = "#f1f5f9"
    fg = "#0f172a"
    accent = "#2563eb"
    root.configure(bg=bg)
    s.configure(".", background=bg)
    s.configure("TFrame", background=bg)
    s.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
    s.configure("TLabelframe", background=bg)
    s.configure(
        "TLabelframe.Label",
        background=bg,
        foreground=accent,
        font=("Segoe UI", 10, "bold"),
    )
    s.configure("TButton", font=("Segoe UI", 10))
    s.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
    s.configure("TEntry", font=("Consolas", 10))
    s.configure("Treeview", font=("Segoe UI", 9), rowheight=26)
    s.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
    s.map(
        "Treeview",
        background=[("selected", "#bfdbfe")],
        foreground=[("selected", "#0f172a")],
    )
    s.configure(
        "TProgressbar",
        thickness=10,
        troughcolor="#e2e8f0",
        background=accent,
        darkcolor=accent,
        lightcolor=accent,
        bordercolor=bg,
    )
    return s


def _load_oui_map() -> dict[str, str]:
    global _OUI_MAP
    with _OUI_LOCK:
        if _OUI_MAP is None:
            path = _resource_dir() / "oui_vendor.zlib"
            m: dict[str, str] = {}
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
    hints: list[str] = []
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


def _local_ipv4():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.25)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def _default_range():
    ip = _local_ipv4()
    if not ip or len(ip.split(".")) != 4:
        return "192.168.1.1", "192.168.1.254"
    b = ".".join(ip.split(".")[:3])
    return f"{b}.1", f"{b}.254"


def _iter_ipv4(start, end):
    a, b = ipaddress.IPv4Address(start.strip()), ipaddress.IPv4Address(end.strip())
    if int(a) > int(b):
        a, b = b, a
    return [str(ipaddress.IPv4Address(i)) for i in range(int(a), int(b) + 1)]


def _ping_one(ip, timeout_ms):
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
        if r.returncode != 0:
            return False
        return "TTL=" in ((r.stdout or "") + (r.stderr or "")).upper()
    except (OSError, subprocess.TimeoutExpired):
        return False


_ARP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")


def _arp_map():
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
    m = {}
    for line in (r.stdout or "").splitlines():
        for x in _ARP.finditer(line):
            ip_s, md = x.group(1), x.group(2).upper()
            m[ip_s] = md.replace("-", ":")
    return m


def _resolve_hostname(ip):
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


def _probe_ports(ip: str, ports: list[tuple[int, str]], timeout: float = 0.35) -> list[str]:
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


class AboutDialog(tk.Toplevel):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master)
        self.title(f"{APP_NAME} — Informazioni")
        _set_window_icon(self)
        _apply_style(self)
        self.resizable(False, False)
        fr = ttk.Frame(self, padding=24)
        fr.pack(fill=tk.BOTH)
        ttk.Label(fr, text=APP_NAME, font=("Segoe UI", 20, "bold")).pack(anchor=tk.W)
        ttk.Label(fr, text=f"Versione {APP_VERSION}", font=("Segoe UI", 10)).pack(
            anchor=tk.W, pady=(2, 14)
        )
        body = (
            f"{APP_COMPANY}\n"
            f"Sviluppatore: {APP_DEVELOPER}\n\n"
            "Licenza: software gratuito. Uso libero per fini personali e commerciali, "
            "senza garanzia e senza obbligo di assistenza. "
            "L'utente è responsabile dell'impiego conforme alle norme vigenti e di operare "
            "solo su reti per le quali dispone di autorizzazione.\n\n"
            "Database vendor OUI derivato dal file manuf del progetto Wireshark."
        )
        ttk.Label(fr, text=body, justify=tk.LEFT, wraplength=440).pack(anchor=tk.W)
        ttk.Button(fr, text="Chiudi", command=self.destroy).pack(pady=(18, 0))
        self.transient(master)
        self.grab_set()




class DeviceDetail(tk.Toplevel):
    PORTS = [
        (80, "HTTP"),
        (443, "HTTPS"),
        (445, "SMB"),
        (22, "SSH"),
        (554, "RTSP"),
        (9100, "JetDirect stampa"),
        (5000, "UPnP/DLNA"),
        (8080, "HTTP alt"),
    ]

    def __init__(self, master: tk.Tk, ip: str, row: tuple):
        super().__init__(master)
        self.title(f"Dispositivo {ip}")
        self.geometry("640x480")
        _set_window_icon(self)
        _apply_style(self)
        self._ip = ip
        f = ttk.Frame(self, padding=8)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=f"IP: {ip}").pack(anchor=tk.W)
        ttk.Label(f, text=f"MAC: {row[2]}").pack(anchor=tk.W)
        ttk.Label(f, text=f"Vendor: {row[3]}").pack(anchor=tk.W)
        ttk.Label(f, text=f"Hostname: {row[4]}").pack(anchor=tk.W)
        ttk.Label(f, text=f"Indizio: {row[5]}").pack(anchor=tk.W)
        self.txt = tk.Text(f, height=16, wrap=tk.WORD, font=("Consolas", 9))
        self.txt.pack(fill=tk.BOTH, expand=True, pady=8)
        bf = ttk.Frame(f)
        bf.pack(fill=tk.X)
        ttk.Button(bf, text="Analizza (NetBIOS + porte)", command=self._analyze).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(bf, text="Copia report", command=self._copy_report).pack(side=tk.LEFT)
        ttk.Button(bf, text="Chiudi", command=self.destroy).pack(side=tk.RIGHT)

    def _analyze(self) -> None:
        self.txt.delete("1.0", tk.END)
        self.txt.insert(tk.END, "Analisi in corso...\n")
        self.update_idletasks()

        def job():
            lines = [f"=== {self._ip} ===\n"]
            hn = _resolve_hostname(self._ip)
            lines.append(f"Hostname (DNS/reverse): {hn or '—'}\n\n")
            lines.append("=== NetBIOS (nbtstat -A) ===\n")
            lines.append(_nbtstat(self._ip) + "\n\n")
            lines.append("=== Porte TCP comuni ===\n")
            openp = _probe_ports(self._ip, self.PORTS)
            lines.append(
                ", ".join(openp) if openp else "Nessuna delle porte testate risponde in apertura.\n"
            )
            lines.append("\n=== Nota ===\n")
            lines.append(
                "Vendor da OUI IEEE; non indica il modello. Il firewall può bloccare le porte.\n"
            )
            report = "".join(lines)
            self.after(0, lambda t=report: self._set_report(t))

        threading.Thread(target=job, daemon=True).start()

    def _set_report(self, text: str) -> None:
        self.txt.delete("1.0", tk.END)
        self.txt.insert(tk.END, text)

    def _copy_report(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.txt.get("1.0", tk.END))
        messagebox.showinfo("Copia", "Report copiato negli appunti.", parent=self)


class App(tk.Tk):
    MAX_HOSTS = 4096
    WORKERS = 48

    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1040x580")
        self.minsize(800, 440)
        _apply_style(self)
        _set_window_icon(self)

        outer = ttk.Frame(self, padding=0)
        outer.pack(fill=tk.BOTH, expand=True)
        head = tk.Frame(outer, bg="#1e293b", height=58)
        head.pack(fill=tk.X)
        head.pack_propagate(False)
        tk.Label(
            head,
            text=APP_NAME,
            font=("Segoe UI", 17, "bold"),
            bg="#1e293b",
            fg="white",
        ).pack(side=tk.LEFT, padx=(18, 8), pady=14)
        tk.Label(
            head,
            text="Scoperta host IPv4 sulla LAN",
            font=("Segoe UI", 9),
            bg="#1e293b",
            fg="#94a3b8",
        ).pack(side=tk.LEFT, pady=14)
        tk.Button(
            head,
            text="?",
            font=("Segoe UI", 12, "bold"),
            bg="#334155",
            fg="white",
            activebackground="#475569",
            activeforeground="white",
            bd=0,
            width=2,
            height=1,
            cursor="hand2",
            command=self._show_about,
        ).pack(side=tk.RIGHT, padx=14, pady=10)

        f = ttk.Frame(outer, padding=(14, 12, 14, 14))
        f.pack(fill=tk.BOTH, expand=True)

        lf_scan = ttk.LabelFrame(f, text=" Intervallo di scansione ", padding=(12, 10))
        lf_scan.pack(fill=tk.X, pady=(0, 10))
        r1 = ttk.Frame(lf_scan)
        r1.pack(fill=tk.X)
        ttk.Label(r1, text="IP iniziale").pack(side=tk.LEFT)
        self.e0 = ttk.Entry(r1, width=16)
        self.e0.pack(side=tk.LEFT, padx=(6, 14))
        ttk.Label(r1, text="IP finale").pack(side=tk.LEFT)
        self.e1 = ttk.Entry(r1, width=16)
        self.e1.pack(side=tk.LEFT, padx=(6, 14))
        a, b = _default_range()
        self.e0.insert(0, a)
        self.e1.insert(0, b)
        ttk.Button(r1, text="Subnet locale", command=self._sub).pack(side=tk.LEFT, padx=(4, 0))

        r2 = ttk.Frame(lf_scan)
        r2.pack(fill=tk.X, pady=(10, 0))
        self.btn = ttk.Button(r2, text="Scansiona", style="Accent.TButton", command=self._go)
        self.btn.pack(side=tk.LEFT)
        ttk.Button(r2, text="Copia selezione", command=self._copy_selection).pack(
            side=tk.LEFT, padx=(10, 0)
        )
        ttk.Button(r2, text="Esporta CSV", command=self._export_csv_dialog).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        self.prog = ttk.Progressbar(r2, mode="determinate", length=280)
        self.prog.pack(side=tk.LEFT, padx=(14, 0), fill=tk.X, expand=True)
        self.st = ttk.Label(r2, text="Pronto", font=("Segoe UI", 9))
        self.st.pack(side=tk.LEFT, padx=(10, 0))

        lf_res = ttk.LabelFrame(f, text=" Risultati ", padding=(8, 8))
        lf_res.pack(fill=tk.BOTH, expand=True)
        tree_fr = ttk.Frame(lf_res)
        tree_fr.pack(fill=tk.BOTH, expand=True)
        headings = ["IP", "Ping", "MAC", "Vendor (OUI)", "Hostname", "Indizio"]
        widths = [118, 48, 138, 198, 198, 132]
        self.tr = ttk.Treeview(
            tree_fr, columns=COLS, show="headings", height=17, selectmode="extended"
        )
        for c, t, w in zip(COLS, headings, widths):
            self.tr.heading(c, text=t)
            self.tr.column(c, width=w, anchor=tk.W if c != "ping" else tk.CENTER)
        sy = ttk.Scrollbar(tree_fr, orient=tk.VERTICAL, command=self.tr.yview)
        self.tr.configure(yscrollcommand=sy.set)
        self.tr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sy.pack(side=tk.RIGHT, fill=tk.Y)

        self.tr.bind("<Control-c>", self._on_copy_shortcut)
        self.tr.bind("<Button-3>", self._popup_menu)
        self.tr.bind("<Double-1>", self._on_double)

        self._th = None
        self._cancel = threading.Event()


    def _show_about(self) -> None:
        AboutDialog(self)

    def _on_copy_shortcut(self, event=None):
        self._copy_selection()
        return "break"

    def _copy_selection(self):
        sels = self.tr.selection()
        if not sels:
            self.st.config(text="Nessuna riga selezionata")
            return
        lines = ["\t".join(str(x) for x in self.tr.item(i, "values")) for i in sels]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.st.config(text=f"Copiate {len(sels)} righe")

    def _export_csv_dialog(self):
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            title="Esporta risultati",
        )
        if path:
            self._export_csv_path(path, only_selection=False)

    def _export_csv_path(self, path: str, only_selection: bool):
        sels = list(self.tr.selection())
        items = sels if only_selection and sels else list(self.tr.get_children())
        if not items:
            messagebox.showwarning("Esporta", "Nessun dato da esportare.")
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fp:
                w = csv.writer(fp, delimiter=";")
                w.writerow(["IP", "Ping", "MAC", "Vendor", "Hostname", "Indizio"])
                for iid in items:
                    w.writerow(self.tr.item(iid, "values"))
            self.st.config(text=f"Esportato: {path}")
        except OSError as e:
            messagebox.showerror("Esporta", str(e))

    def _popup_menu(self, event):
        iid = self.tr.identify_row(event.y)
        if iid and iid not in self.tr.selection():
            self.tr.selection_set(iid)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Copia selezione", command=self._copy_selection)
        menu.add_command(label="Dettaglio dispositivo…", command=self._open_detail_selected)
        menu.add_separator()
        menu.add_command(
            label="Esporta CSV (tutte le righe)",
            command=lambda: self._export_csv_quick(True),
        )
        menu.add_command(
            label="Esporta CSV (solo selezione)",
            command=lambda: self._export_csv_quick(False),
        )
        menu.add_separator()
        menu.add_command(label="Informazioni…", command=self._show_about)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _export_csv_quick(self, all_rows: bool):
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            title="Esporta CSV",
        )
        if path:
            self._export_csv_path(path, only_selection=not all_rows)

    def _open_detail_selected(self):
        sels = self.tr.selection()
        if not sels:
            messagebox.showinfo("Dettaglio", "Seleziona una riga.")
            return
        vals = tuple(self.tr.item(sels[0], "values"))
        if len(vals) >= 6:
            DeviceDetail(self, vals[0], vals)

    def _on_double(self, event):
        iid = self.tr.identify_row(event.y)
        if not iid:
            return
        vals = tuple(self.tr.item(iid, "values"))
        if len(vals) >= 6:
            DeviceDetail(self, vals[0], vals)

    def _sub(self):
        a, b = _default_range()
        self.e0.delete(0, tk.END)
        self.e0.insert(0, a)
        self.e1.delete(0, tk.END)
        self.e1.insert(0, b)

    def _go(self):
        if self._th and self._th.is_alive():
            self._cancel.set()
            self.st.config(text="Interruzione...")
            return
        s0, s1 = self.e0.get().strip(), self.e1.get().strip()
        try:
            ipaddress.IPv4Address(s0)
            ipaddress.IPv4Address(s1)
        except ValueError:
            messagebox.showerror("Errore", "IPv4 non validi.")
            return
        hosts = _iter_ipv4(s0, s1)
        n = len(hosts)
        if n > self.MAX_HOSTS:
            messagebox.showerror("Errore", f"Max {self.MAX_HOSTS} indirizzi.")
            return
        self._cancel.clear()
        self.btn.config(text="Interrompi")
        for i in self.tr.get_children():
            self.tr.delete(i)
        self.prog["maximum"] = n
        self.prog["value"] = 0
        self.st.config(text=f"Scansione {n} host...")
        self._th = threading.Thread(target=self._run, args=(hosts,), daemon=True)
        self._th.start()

    def _run(self, hosts):
        timeout_ms = 750
        alive = []
        done = 0
        total = len(hosts)
        try:
            _load_oui_map()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.WORKERS) as ex:
                futs = {ex.submit(_ping_one, ip, timeout_ms): ip for ip in hosts}
                for fu in concurrent.futures.as_completed(futs):
                    if self._cancel.is_set():
                        break
                    ip = futs[fu]
                    try:
                        ok = fu.result()
                    except Exception:
                        ok = False
                    if ok:
                        alive.append(ip)
                    done += 1
                    if done % 8 == 0 or done == total:
                        self.after(0, lambda d=done, t=total: self._upd(d, t))
            if self._cancel.is_set():
                self.after(0, lambda: self._done("Interrotto"))
                return
            time.sleep(0.4)
            arp = _arp_map()
            rows = []
            for ip in sorted(alive, key=lambda x: int(ipaddress.IPv4Address(x))):
                mac = arp.get(ip, "")
                v = _vendor_from_mac(mac) if mac else ""
                rows.append((ip, "OK", mac or "—", v or "—", "...", "—"))
            self.after(0, lambda r=rows: self._fill(r))

            def res():
                for it in self.tr.get_children():
                    vals = list(self.tr.item(it, "values"))
                    if len(vals) >= 6 and vals[4] == "...":
                        hn = _resolve_hostname(vals[0]) or "—"
                        vals[4] = hn
                        vals[5] = _quick_hint(hn, vals[3], vals[2])
                        self.tr.item(it, values=vals)

            threading.Thread(target=res, daemon=True).start()
            self.after(0, lambda n=len(alive): self._done(f"Trovati {n} host"))
        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda m=err_msg: self._err(m))

    def _upd(self, d, t):
        self.prog["value"] = d
        self.st.config(text=f"Ping {d}/{t}")

    def _fill(self, rows):
        for r in rows:
            self.tr.insert("", tk.END, values=r)

    def _done(self, msg):
        self.prog["value"] = self.prog["maximum"]
        self.st.config(text=msg)
        self.btn.config(text="Scansiona")
        self._th = None

    def _err(self, e):
        self.st.config(text="Errore")
        self.btn.config(text="Scansiona")
        self._th = None
        messagebox.showerror("Errore", e)


def main():
    if sys.platform != "win32":
        print("Solo Windows.")
        sys.exit(1)
    App().mainloop()


if __name__ == "__main__":
    main()
