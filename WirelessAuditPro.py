from __future__ import annotations

# ============================================================
#   Wireless Audit Pro — Integrated Wireless Assessment Suite
#   Target OS : Windows 10/11 + Kali WSL2 | Intel/Alfa AWUS1900
#   Version   : 3.3.1
# ============================================================

import customtkinter as ctk
import tkinter.ttk as ttk
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import shutil
import re
import threading
import datetime
import html
import io
import time
import os
import csv
import json
import math
import queue
import sqlite3
import statistics
import tempfile
import platform
import hashlib
import webbrowser
import locale
import sys
from collections import defaultdict
from contextlib import closing
from xml.sax.saxutils import escape as xml_escape
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict

try:
    import serial
    from serial.tools import list_ports
except Exception:  # GPS serial is optional until a receiver is connected.
    serial = None  # type: ignore[assignment]
    list_ports = None  # type: ignore[assignment]

try:
    from tkintermapview import TkinterMapView
    from PIL import Image as PILImage, ImageTk as PILImageTk
    MAP_WIDGET_AVAILABLE = True
except Exception:
    TkinterMapView = None  # type: ignore[assignment,misc]
    PILImage = None  # type: ignore[assignment]
    PILImageTk = None  # type: ignore[assignment]
    MAP_WIDGET_AVAILABLE = False

try:
    import requests
except Exception:
    requests = None  # type: ignore[assignment]

try:
    from speedtest import Speedtest
except Exception:
    Speedtest = None  # type: ignore[assignment,misc]

# =========================================================
# === CONSTANTES Y LÍMITES ===
# =========================================================
MAX_PREFIX_LENGTH   = 50
MAX_SSID_LENGTH     = 32
MAX_IP_LENGTH       = 45
REPORT_DEFAULT_NAME = "Wireless_Audit_Pro"
BASE_DIR            = Path(__file__).resolve().parent
CAPTURE_DIR         = BASE_DIR / "captures"
REPORTS_DIR         = BASE_DIR / "reports"
DATA_DIR            = BASE_DIR / "data"
EXPORTS_DIR         = BASE_DIR / "exports"
WARDRIVE_DB         = DATA_DIR / "wardrive.sqlite3"
MAP_CACHE_DB        = DATA_DIR / "map_tiles.sqlite"
TOOL_TIMEOUT        = 8
NETSH_SLEEP         = 1.5
CONNECT_SLEEP       = 4.0
VERSION             = "3.3.1"
WLAN_SCAN_LOCK      = threading.Lock()

APP_BG              = "#050b08"
PANEL_BG            = "#0a1510"
PANEL_ALT           = "#0d1d16"
RADAR_GREEN         = "#54ff72"
RADAR_DIM           = "#174d27"
CYAN                = "#41e5ff"
WARNING             = "#ffb84d"
DANGER              = "#ff5964"
BUTTON_IDLE         = "#4b5563"
BUTTON_START        = "#238636"
BUTTON_STOP         = "#7d2e2e"
MAP_MAX_MARKERS     = 120
MAP_UPDATES_PER_TICK = 18
MAP_MIN_TRACK_KM    = 0.003

# ── Fingerprints RTL8814AU ─────────────────────────────────
ALFA_FINGERPRINTS: List[str] = [
    "alfa", "awus1900", "rtl8814", "8814au", "realtek 8814", "rtl88x2bu", "rtl88x2cu",
    "realtek 802.11ac", "802.11ac dual band wireless",
    "0bda:8813", "0bda:881a", "0bda:a811",
    "vid_0bda", "pid_8813", "pid_881a",
    "realtek rtl8814",
]

# ── Rutas Windows donde suelen instalarse las tools ───────
WIN_TOOL_PATHS: Dict[str, List[str]] = {
    "nmap": [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ],
    "tshark": [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ],
    "aircrack-ng": [
        r"C:\Program Files\aircrack-ng\aircrack-ng.exe",
        r"C:\aircrack-ng\aircrack-ng.exe",
        r"C:\tools\aircrack-ng\aircrack-ng.exe",
    ],
    "hashcat": [
        r"C:\Program Files\hashcat\hashcat.exe",
        r"C:\hashcat\hashcat.exe",
        r"C:\tools\hashcat\hashcat.exe",
        r"C:\ProgramData\chocolatey\bin\hashcat.exe",
    ],
    "choco": [
        r"C:\ProgramData\chocolatey\bin\choco.exe",
        r"C:\ProgramData\chocolatey\choco.exe",
    ],
}

TOOLS_CONFIG: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "choco"  : "nmap",
        "winget" : "Insecure.Nmap",
        "url"    : "https://nmap.org/download.html",
        "desc"   : "Network scanner — host discovery y servicios post-conexion",
    },
    "tshark": {
        "choco"  : "wireshark",
        "winget" : "WiresharkFoundation.Wireshark",
        "url"    : "https://www.wireshark.org/download.html",
        "desc"   : "Captura de paquetes 802.11 (incluye Npcap)",
    },
    "aircrack-ng": {
        "choco"  : None,
        "winget" : None,
        "url"    : "https://www.aircrack-ng.org/downloads.html",
        "desc"   : "Cracking WPA/WEP offline desde .cap / .hccapx",
    },
    "hashcat": {
        "choco"  : "hashcat",
        "winget" : None,
        "url"    : "https://hashcat.net/hashcat/",
        "desc"   : "GPU cracker — PMKID/HCCAPX modo 22000/2500",
    },
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# =========================================================
# === OUI DATABASE ===
# =========================================================
OUI_DB: Dict[str, str] = {
    "00:14:BF": "Cisco-Linksys", "00:23:69": "Cisco",    "00:1D:7E": "Cisco",
    "14:CC:20": "TP-Link",       "C0:25:E9": "TP-Link",  "F8:1A:67": "TP-Link",
    "50:C7:BF": "TP-Link",       "A0:F3:C1": "TP-Link",  "00:26:5A": "D-Link",
    "00:1E:58": "D-Link",        "00:21:29": "Netgear",  "00:26:F2": "Netgear",
    "00:24:E4": "Huawei",        "00:25:9E": "Huawei",   "00:15:D1": "Arris",
    "18:A6:F7": "Ubiquiti",      "24:A4:3C": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "DC:A9:04": "ASUSTek",       "00:1A:92": "ASUSTek",  "B0:48:7A": "Mikrotik",
    "4C:5E:0C": "Mikrotik",      "74:DA:38": "Edimax",   "00:1A:11": "Google",
    "F4:F5:E8": "Google",        "1C:3B:F3": "Ruckus",   "00:22:3F": "Aruba/HP",
    "9C:1C:12": "Aruba",         "00:1E:E3": "Apple",    "00:23:12": "Apple",
    "AC:BC:32": "Apple",         "00:0C:29": "VMware",   "00:50:56": "VMware",
    "00:1B:77": "Intel",         "00:1C:BF": "Samsung",  "5C:49:79": "Samsung",
    "B0:19:C6": "Xiaomi",        "50:64:2B": "Xiaomi",   "8C:BE:BE": "Xiaomi",
    "00:14:22": "Dell",          "00:25:9C": "Cisco",
}


# =========================================================
# === HELPERS Y VALIDADORES ===
# =========================================================
def decode_console_bytes(data: bytes) -> str:
    """Decode Windows console output without corrupting Spanish netsh labels."""
    if data and data.count(b"\x00") > len(data) // 6:
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    candidates: List[str] = ["utf-8"]
    if os.name == "nt":
        try:
            import ctypes
            candidates.append(f"cp{ctypes.windll.kernel32.GetOEMCP()}")
        except Exception:
            pass
    candidates.extend([locale.getpreferredencoding(False), "cp850", "cp1252", "latin-1"])
    for encoding in dict.fromkeys(candidates):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def hidden_process_kwargs() -> Dict[str, Any]:
    """Prevent console utilities from flashing terminal windows behind the GUI."""
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    return {}


def run_console(args: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess[str]:
    """Run a command and return correctly decoded stdout/stderr."""
    result = subprocess.run(
        args, capture_output=True, timeout=timeout, check=False,
        **hidden_process_kwargs(),
    )
    return subprocess.CompletedProcess(
        args=result.args,
        returncode=result.returncode,
        stdout=decode_console_bytes(result.stdout or b""),
        stderr=decode_console_bytes(result.stderr or b""),
    )


def open_local_path(path: Path) -> None:
    """Open a local folder only after an explicit click, on Windows or Linux."""
    if os.name == "nt":
        os.startfile(str(path))  # type: ignore[attr-defined]
        return
    subprocess.Popen(
        ["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        **hidden_process_kwargs(),
    )


def parse_signal_percent(value: str) -> int:
    match = re.search(r"(-?\d+)", value or "")
    if not match:
        return 0
    raw = int(match.group(1))
    if raw < 0:  # Native RSSI dBm.
        return max(0, min(100, (raw + 100) * 2))
    return max(0, min(100, raw))


def signal_dbm(value: str) -> int:
    match = re.search(r"(-?\d+)", value or "")
    if not match:
        return -100
    raw = int(match.group(1))
    return raw if raw < 0 else round((max(0, min(100, raw)) / 2) - 100)


def proximity_label(value: str) -> str:
    pct = parse_signal_percent(value)
    if pct >= 82:
        return "MUY CERCA"
    if pct >= 64:
        return "CERCA"
    if pct >= 44:
        return "MEDIA"
    if pct:
        return "LEJOS"
    return "SIN DATO"


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", value)


def auth_mode(auth: str, cipher: str) -> str:
    """Return a WiGLE-compatible AuthMode value."""
    a = (auth or "").upper()
    c = (cipher or "").upper()
    if "OPEN" in a or "ABIERTA" in a or a in ("", "NINGUNO", "NONE"):
        return "[ESS]"
    parts: List[str] = []
    if "WPA3" in a:
        parts.append("WPA3-SAE")
    elif "WPA2" in a:
        parts.append("WPA2-PSK" if "ENTERPRISE" not in a else "WPA2-EAP")
    elif "WPA" in a:
        parts.append("WPA-PSK" if "ENTERPRISE" not in a else "WPA-EAP")
    elif "WEP" in a:
        parts.append("WEP")
    if "CCMP" in c or "AES" in c:
        parts.append("CCMP")
    elif "TKIP" in c:
        parts.append("TKIP")
    return "[" + "-".join(parts or ["UNKNOWN"]) + "][ESS]"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_html(value: Any) -> str:
    return html.escape(str(value))

def clamp_str(text: str, max_len: int) -> str:
    return text[:max_len]

def get_vendor(bssid: str) -> str:
    prefix = bssid[:8].upper().replace("-", ":")
    return OUI_DB.get(prefix, "Desconocido")

def security_score(auth: str, cipher: str) -> Tuple[int, str, str]:
    a = auth.upper()
    c = cipher.upper()
    if "WPA3" in a:
        return 94, "WPA3", "Configuracion robusta; validar PMF requerido y modo transicion."
    if "WPA2" in a and "CCMP" in c:
        return 78, "WPA2/AES", "Validar PMF, WPS y fortaleza PSK; PMKID no se presume."
    if "WPA2" in a and "TKIP" in c:
        return 48, "WPA2/TKIP", "Deshabilitar TKIP y mantener solo CCMP/AES."
    if "WPA2" in a:
        return 65, "WPA2", "Validar cifrado, PMF, WPS y fortaleza de la credencial."
    if "WPA" in a:
        return 28, "WPA v1", "Migrar a WPA2-CCMP o WPA3; WPA/TKIP esta obsoleto."
    if "WEP" in a:
        return 5, "WEP CRITICO", "Sustituir WEP inmediatamente por WPA2/WPA3."
    if "OPEN" in a or a in ("", "NINGUNO", "NONE", "ABIERTA"):
        return 0, "OPEN CRITICO", "Sin autenticacion; usar OWE, WPA2 o WPA3."
    return 50, "Desconocido", "No se pudo determinar el esquema de auth."

def signal_to_dbm(s: str) -> str:
    if s:
        pct = parse_signal_percent(s)
        dbm = signal_dbm(s)
        return f"{pct}% ({dbm} dBm)"
    return s

def find_tool_binary(name: str) -> Optional[str]:
    """
    Busca el binario de una herramienta:
    1. shutil.which  (PATH del sistema)
    2. Rutas hardcoded comunes en Windows
    """
    found = shutil.which(name)
    if found:
        return found
    # Windows: sin extension .exe a veces which falla
    found = shutil.which(name + ".exe")
    if found:
        return found
    # Rutas de instalacion tipicas en Windows
    for path in WIN_TOOL_PATHS.get(name, []):
        if os.path.isfile(path):
            return path
    return None


class DragonRadarCanvas(tk.Canvas):
    """Animated Dragon Radar-inspired display for nearby Wi-Fi networks."""

    def __init__(self, master: Any, **kwargs: Any) -> None:
        kwargs.setdefault("background", "#020704")
        kwargs.setdefault("highlightthickness", 0)
        super().__init__(master, **kwargs)
        self.networks: List[NetworkEntry] = []
        self.sweep_angle = 0.0
        self._pulse = 0.0
        self._running = False
        self.bind("<Configure>", lambda _: self._draw())
        self.after(60, self._animate)

    def set_networks(self, networks: List[NetworkEntry]) -> None:
        self.networks = [n for n in networks if n.bssid]
        self._draw()

    def set_running(self, running: bool) -> None:
        self._running = running
        self._draw()

    @staticmethod
    def _color(network: NetworkEntry) -> str:
        auth = (network.auth or "").upper()
        if "OPEN" in auth or "ABIERTA" in auth or auth in ("", "NINGUNO", "NONE"):
            return DANGER
        if "WEP" in auth or "TKIP" in (network.cipher or "").upper():
            return WARNING
        if "WPA3" in auth:
            return CYAN
        return RADAR_GREEN

    @staticmethod
    def _position(network: NetworkEntry, radius: float) -> Tuple[float, float, float]:
        seed = int(hashlib.sha256((network.bssid or network.ssid).encode("utf-8")).hexdigest()[:8], 16)
        angle = math.radians(seed % 360)
        pct = parse_signal_percent(network.signal)
        # Strong signals appear close to the centre, weak ones near the edge.
        jitter = (((seed >> 9) % 15) - 7) / 100.0
        radial = radius * max(0.12, min(0.96, 0.18 + (1.0 - pct / 100.0) * 0.76 + jitter))
        return math.cos(angle) * radial, math.sin(angle) * radial, angle

    def _animate(self) -> None:
        if not self.winfo_exists():
            return
        if self._running:
            self.sweep_angle = (self.sweep_angle + 2.8) % 360
            self._pulse = (self._pulse + 0.13) % (math.pi * 2)
            self._draw()
        self.after(60, self._animate)

    def _draw(self) -> None:
        width = max(320, self.winfo_width())
        height = max(320, self.winfo_height())
        cx, cy = width / 2, height / 2
        radius = max(120.0, min(width, height) * 0.43)
        self.delete("all")

        # Subtle green glow built with concentric dark rings.
        for glow in range(8, 0, -1):
            pad = glow * 3
            shade = "#031109" if glow > 4 else "#052010"
            self.create_oval(cx - radius - pad, cy - radius - pad,
                             cx + radius + pad, cy + radius + pad,
                             outline=shade, width=2)

        self.create_oval(cx - radius, cy - radius, cx + radius, cy + radius,
                         fill="#03150a", outline=RADAR_GREEN, width=3)
        for idx, fraction in enumerate((0.25, 0.50, 0.75, 1.0), 1):
            ring = radius * fraction
            self.create_oval(cx - ring, cy - ring, cx + ring, cy + ring,
                             outline=RADAR_DIM if fraction < 1 else RADAR_GREEN,
                             width=1 if fraction < 1 else 2)
            labels = {1: "MUY CERCA", 2: "CERCA", 3: "MEDIA", 4: "LEJOS"}
            self.create_text(cx + 8, cy - ring + 9, text=labels[idx],
                             fill="#2b8844", anchor="nw", font=("Consolas", 8, "bold"))

        # Crosshair and diagonal grid.
        for angle in range(0, 360, 45):
            rad = math.radians(angle)
            x = cx + math.cos(rad) * radius
            y = cy + math.sin(rad) * radius
            self.create_line(cx, cy, x, y, fill="#103a1e", width=1)

        # Multi-line sweep creates a luminous sector without image assets.
        for offset in range(0, 19, 3):
            angle = math.radians(self.sweep_angle - offset)
            x = cx + math.cos(angle) * radius
            y = cy + math.sin(angle) * radius
            color = RADAR_GREEN if offset == 0 else ("#36b652" if offset < 9 else "#185b2c")
            self.create_line(cx, cy, x, y, fill=color, width=3 if offset == 0 else 1)

        now = time.time()
        ordered = sorted(self.networks, key=lambda item: parse_signal_percent(item.signal), reverse=True)
        for index, network in enumerate(ordered):
            dx, dy, angle = self._position(network, radius)
            x, y = cx + dx, cy + dy
            color = self._color(network)
            seed = int(hashlib.md5(network.bssid.encode("utf-8")).hexdigest()[:4], 16)
            pulse = 2.0 + 1.8 * (1 + math.sin(now * 4 + seed)) / 2
            self.create_oval(x - 10 - pulse, y - 10 - pulse, x + 10 + pulse, y + 10 + pulse,
                             outline="#164b25", width=2)
            self.create_oval(x - 5, y - 5, x + 5, y + 5,
                             fill=color, outline="#eaffee", width=1)
            # The table retains every BSSID. On the radar, label only the
            # strongest contacts to keep the visual readable in dense areas.
            if index < 14:
                label = network.ssid or "<OCULTO>"
                if len(label) > 18:
                    label = label[:16] + "…"
                anchor = "w" if math.cos(angle) >= 0 else "e"
                lx = x + 10 if anchor == "w" else x - 10
                self.create_text(lx, y - 7, text=label, anchor=anchor,
                                 fill="#d9ffe2", font=("Consolas", 9, "bold"))
                self.create_text(lx, y + 8,
                                 text=f"{network.signal or 'N/A'} · CH {network.channel or '?'} · {proximity_label(network.signal)}",
                                 anchor=anchor, fill="#65c97b", font=("Consolas", 7))

        # Dragon-ball style centre marker.
        centre_size = 19 + 2 * math.sin(self._pulse)
        self.create_oval(cx - centre_size, cy - centre_size, cx + centre_size, cy + centre_size,
                         fill="#ff9d28", outline="#ffe86b", width=3)
        self.create_text(cx, cy, text="★", fill="#e52b2b", font=("Segoe UI Symbol", 24, "bold"))
        self.create_text(14, 14, anchor="nw", text=f"RADAR 802.11  ·  {len(self.networks):02d} OBJETIVOS",
                         fill=RADAR_GREEN, font=("Consolas", 11, "bold"))
        self.create_text(width - 14, 14, anchor="ne", text=datetime.datetime.now().strftime("%H:%M:%S"),
                         fill="#4da962", font=("Consolas", 10))


class SpectrumCanvas(tk.Canvas):
    """Live 2.4/5 GHz channel view rendered from the same scan as the radar."""

    PALETTE = (
        "#54ff72", "#41e5ff", "#ff6b81", "#ffe66d", "#b983ff",
        "#6fffe9", "#ff9f43", "#7bed9f", "#70a1ff", "#ff7f50",
    )

    def __init__(self, master: Any, **kwargs: Any) -> None:
        kwargs.setdefault("background", "#020704")
        kwargs.setdefault("highlightthickness", 0)
        super().__init__(master, **kwargs)
        self.networks: List[NetworkEntry] = []
        self.bind("<Configure>", lambda _: self._draw())

    def set_networks(self, networks: List[NetworkEntry]) -> None:
        self.networks = [item for item in networks if item.bssid and str(item.channel).isdigit()]
        self._draw()

    @staticmethod
    def _band(network: NetworkEntry) -> str:
        if getattr(network, "frequency_mhz", 0) >= 5900:
            return "5 / 6 GHz"
        channel = int(network.channel or 0)
        return "2.4 GHz" if 1 <= channel <= 14 else "5 / 6 GHz"

    def _draw_band(
        self, title: str, items: List[NetworkEntry], bounds: Tuple[float, float, float, float],
        channel_min: int, channel_max: int, ticks: List[int],
    ) -> None:
        left, top, right, bottom = bounds
        width = max(1.0, right - left)
        height = max(1.0, bottom - top)
        self.create_rectangle(left, top, right, bottom, fill="#06110b", outline="#28693b", width=2)
        self.create_text(left + 14, top + 12, anchor="nw", text=title,
                         fill=WARNING if title.startswith("2.4") else CYAN,
                         font=("Consolas", 13, "bold"))
        self.create_text(right - 14, top + 12, anchor="ne", text=f"{len(items)} AP",
                         fill="#91a99a", font=("Consolas", 10, "bold"))

        chart_top, chart_bottom = top + 42, bottom - 28
        for level in (25, 50, 75, 100):
            y = chart_bottom - (chart_bottom - chart_top) * level / 100.0
            self.create_line(left + 38, y, right - 12, y, fill="#102a19", width=1)
            self.create_text(left + 31, y, anchor="e", text=str(level),
                             fill="#45664f", font=("Consolas", 8))
        self.create_text(left + 8, (chart_top + chart_bottom) / 2, anchor="w", angle=90,
                         text="SEÑAL %", fill="#45664f", font=("Consolas", 8, "bold"))

        def channel_x(channel: int) -> float:
            span = max(1, channel_max - channel_min)
            channel = max(channel_min, min(channel_max, channel))
            return left + 42 + (right - left - 58) * (channel - channel_min) / span

        for channel in ticks:
            x = channel_x(channel)
            self.create_line(x, chart_bottom, x, chart_bottom + 4, fill="#688a72")
            self.create_text(x, chart_bottom + 8, anchor="n", text=str(channel),
                             fill="#8ea898", font=("Consolas", 9))

        ordered = sorted(items, key=lambda item: parse_signal_percent(item.signal), reverse=True)
        label_slots: List[Tuple[float, float]] = []
        for index, network in enumerate(reversed(ordered)):
            channel = int(network.channel)
            pct = parse_signal_percent(network.signal)
            center = channel_x(channel)
            # Width is an occupancy estimate. Exact channel width is unavailable
            # through netsh, so the curve never claims 20/40/80 MHz telemetry.
            half_width = max(12.0, width * (0.055 if title.startswith("2.4") else 0.035))
            peak_y = chart_bottom - (chart_bottom - chart_top) * pct / 100.0
            points: List[float] = [center - half_width, chart_bottom]
            for step in range(25):
                ratio = step / 24.0
                x = center - half_width + ratio * half_width * 2
                bell = math.exp(-0.5 * ((ratio - 0.5) / 0.22) ** 2)
                y = chart_bottom - (chart_bottom - peak_y) * bell
                points.extend((x, y))
            points.extend((center + half_width, chart_bottom))
            color = self.PALETTE[index % len(self.PALETTE)]
            self.create_polygon(points, fill=color, stipple="gray25", outline=color, width=2)

            if network in ordered[:12]:
                label = network.ssid or "<OCULTO>"
                if len(label) > 20:
                    label = label[:18] + "…"
                label_y = max(chart_top + 3, peak_y - 16)
                for _ in range(8):
                    if not any(abs(center - lx) < 58 and abs(label_y - ly) < 14 for lx, ly in label_slots):
                        break
                    label_y = min(chart_bottom - 12, label_y + 14)
                label_slots.append((center, label_y))
                self.create_text(center, label_y, text=label, fill=color,
                                 font=("Consolas", 9, "bold"))

    def _draw(self) -> None:
        if not self.winfo_exists():
            return
        width = max(640, self.winfo_width())
        height = max(480, self.winfo_height())
        self.delete("all")
        margin = 16
        gap = 12
        mid = height * 0.54
        band24 = [item for item in self.networks if self._band(item) == "2.4 GHz"]
        band5 = [item for item in self.networks if self._band(item) != "2.4 GHz"]
        self._draw_band("2.4 GHz", band24, (margin, margin, width - margin, mid - gap / 2),
                        1, 14, list(range(1, 15)))
        self._draw_band("5 / 6 GHz", band5, (margin, mid + gap / 2, width - margin, height - margin),
                        1, 233, [1, 36, 64, 100, 132, 149, 177, 197, 213, 229])


if MAP_WIDGET_AVAILABLE and TkinterMapView is not None:
    class ResponsiveMapView(TkinterMapView):
        """TkinterMapView variant that never creates Tk images off the UI thread."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._tile_queue_lock = threading.Lock()
            self._tile_cache_lock = threading.Lock()
            self._tile_fetch_slots = threading.BoundedSemaphore(4)
            self._raw_tile_cache: Dict[str, Any] = {}
            super().__init__(*args, **kwargs)
            # The upstream widget initially queues Berlin tiles before the caller
            # can choose a position. Discard them to avoid useless network churn.
            with self._tile_queue_lock:
                self.image_load_queue_tasks.clear()
                self.image_load_queue_results.clear()

        def pre_cache(self) -> None:
            # Upstream downloads a radius of eight tiles for every position. The
            # visible grid plus the explicit offline-cache button are sufficient.
            while self.running:
                time.sleep(0.25)

        @staticmethod
        def _tile_key(zoom: int, x: int, y: int) -> str:
            # Keep the upstream key format because get_tile_image_from_cache uses it.
            return f"{zoom}{x}{y}"

        def _remember_raw_tile(self, key: str, image: Any) -> Any:
            with self._tile_cache_lock:
                self._raw_tile_cache[key] = image
                while len(self._raw_tile_cache) > 512:
                    self._raw_tile_cache.pop(next(iter(self._raw_tile_cache)))
            return image

        def request_image(self, zoom: int, x: int, y: int, db_cursor: Any = None) -> Any:
            key = self._tile_key(zoom, x, y)
            cached = self.tile_image_cache.get(key)
            if cached is not None:
                return cached
            with self._tile_cache_lock:
                raw_cached = self._raw_tile_cache.get(key)
            if raw_cached is not None:
                return raw_cached

            image_bytes: Optional[bytes] = None
            if db_cursor is not None:
                try:
                    db_cursor.execute(
                        "SELECT tile_image FROM tiles WHERE zoom=? AND x=? AND y=? AND server=?",
                        (zoom, x, y, self.tile_server),
                    )
                    row = db_cursor.fetchone()
                    if row:
                        image_bytes = bytes(row[0])
                    elif self.use_database_only:
                        return self.empty_tile_image
                except sqlite3.Error:
                    if self.use_database_only:
                        return self.empty_tile_image

            if image_bytes is None:
                if self.use_database_only or requests is None:
                    return self.empty_tile_image
                try:
                    url = self.tile_server.replace("{x}", str(x)).replace("{y}", str(y)).replace("{z}", str(zoom))
                    response = requests.get(
                        url, timeout=(2.5, 6.0),
                        headers={"User-Agent": f"WirelessAuditPro/{VERSION} local-map"},
                    )
                    response.raise_for_status()
                    image_bytes = response.content
                except Exception:
                    return self.empty_tile_image

            try:
                if PILImage is None:
                    return self.empty_tile_image
                with PILImage.open(io.BytesIO(image_bytes)) as source:
                    image = source.convert("RGB")
                    image.load()
                return self._remember_raw_tile(key, image)
            except Exception:
                return self.empty_tile_image

        def load_images_background(self) -> None:
            while self.running:
                task = None
                with self._tile_queue_lock:
                    if self.image_load_queue_tasks:
                        task = self.image_load_queue_tasks.pop()
                if task is None:
                    time.sleep(0.025)
                    continue
                zoom, x, y = task[0]
                canvas_tile = task[1]
                with self._tile_fetch_slots:
                    image = self.get_tile_image_from_cache(zoom, x, y)
                    if image is False:
                        connection = None
                        cursor = None
                        if self.database_path is not None:
                            try:
                                connection = sqlite3.connect(self.database_path, timeout=0.5)
                                connection.execute("PRAGMA busy_timeout=500")
                                cursor = connection.cursor()
                            except sqlite3.Error:
                                connection = None
                                cursor = None
                        try:
                            image = self.request_image(zoom, x, y, db_cursor=cursor)
                        finally:
                            if connection is not None:
                                connection.close()
                with self._tile_queue_lock:
                    self.image_load_queue_results.append(((zoom, x, y), canvas_tile, image))

        def update_canvas_tile_images(self) -> None:
            processed = 0
            while self.running and processed < 8:
                with self._tile_queue_lock:
                    if not self.image_load_queue_results:
                        break
                    result = self.image_load_queue_results.pop(0)
                zoom, x, y = result[0]
                canvas_tile, image = result[1], result[2]
                if PILImage is not None and isinstance(image, PILImage.Image):
                    try:
                        image = PILImageTk.PhotoImage(image, master=self.canvas)
                        key = self._tile_key(zoom, x, y)
                        self.tile_image_cache[key] = image
                        with self._tile_cache_lock:
                            self._raw_tile_cache.pop(key, None)
                    except Exception:
                        image = self.empty_tile_image
                if zoom == round(self.zoom):
                    canvas_tile.set_image(image)
                processed += 1
            if self.running:
                self.after(25, self.update_canvas_tile_images)
else:
    ResponsiveMapView = None  # type: ignore[assignment,misc]


@dataclass
class GPSFix:
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    accuracy: Optional[float] = None
    satellites: int = 0
    speed_kmh: Optional[float] = None
    heading: Optional[float] = None
    source: str = "Sin GPS"
    timestamp: str = ""

    @property
    def valid(self) -> bool:
        return self.latitude is not None and self.longitude is not None


class GPSManager:
    """GPS provider supporting Windows Location and USB/Bluetooth NMEA receivers."""

    def __init__(self, log_cb: Any) -> None:
        self.log_cb = log_cb
        self.latest = GPSFix()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def sources() -> List[str]:
        values = ["Windows Location", "Sin GPS (solo inventario)"]
        if list_ports:
            try:
                for port in list_ports.comports():
                    values.insert(1, f"NMEA {port.device} · {port.description}")
            except Exception:
                pass
        return values

    def start(self, source: str) -> None:
        self.stop()
        stop_event = threading.Event()
        self._stop = stop_event
        if source.startswith("NMEA "):
            port = source.split(" ", 2)[1]
            self._thread = threading.Thread(target=self._serial_loop, args=(port, stop_event), daemon=True)
        elif source == "Windows Location":
            self._thread = threading.Thread(target=self._windows_loop, args=(stop_event,), daemon=True)
        else:
            with self._lock:
                self.latest = GPSFix(source="Sin GPS", timestamp=datetime.datetime.now().isoformat())
            self.log_cb("GPS desactivado: se registraran redes sin coordenadas.", "WARNING")
            return
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        # Never join from the Tk main thread: Windows Location may still be
        # finishing a bounded sensor query and the interface must stay fluid.
        self._thread = None

    def snapshot(self) -> GPSFix:
        with self._lock:
            return GPSFix(**asdict(self.latest))

    @staticmethod
    def _nmea_coord(raw: str, hemisphere: str) -> Optional[float]:
        if not raw:
            return None
        try:
            value = float(raw)
            degrees = int(value // 100)
            minutes = value - degrees * 100
            decimal = degrees + minutes / 60.0
            if hemisphere in ("S", "W"):
                decimal *= -1
            return decimal
        except ValueError:
            return None

    @classmethod
    def parse_nmea(cls, line: str) -> Optional[GPSFix]:
        fields = line.strip().split(",")
        if not fields:
            return None
        sentence = fields[0]
        try:
            if sentence.endswith("GGA") and len(fields) >= 10 and fields[6] not in ("", "0"):
                lat = cls._nmea_coord(fields[2], fields[3])
                lon = cls._nmea_coord(fields[4], fields[5])
                return GPSFix(
                    latitude=lat,
                    longitude=lon,
                    altitude=float(fields[9]) if fields[9] else None,
                    accuracy=float(fields[8]) * 5 if fields[8] else None,
                    satellites=int(fields[7] or 0),
                    source="NMEA",
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                )
            if sentence.endswith("RMC") and len(fields) >= 7 and fields[2] == "A":
                return GPSFix(
                    latitude=cls._nmea_coord(fields[3], fields[4]),
                    longitude=cls._nmea_coord(fields[5], fields[6]),
                    speed_kmh=float(fields[7]) * 1.852 if len(fields) > 7 and fields[7] else None,
                    heading=float(fields[8]) if len(fields) > 8 and fields[8] else None,
                    source="NMEA",
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                )
        except (ValueError, IndexError):
            return None
        return None

    def _serial_loop(self, port: str, stop_event: threading.Event) -> None:
        if serial is None:
            self.log_cb("pyserial no esta disponible.", "ERROR")
            return
        self.log_cb(f"GPS NMEA escuchando en {port}.", "INFO")
        try:
            with serial.Serial(port, 9600, timeout=1) as device:
                while not stop_event.is_set():
                    raw = device.readline().decode("ascii", errors="ignore")
                    fix = self.parse_nmea(raw)
                    if fix and fix.valid:
                        fix.source = f"NMEA {port}"
                        with self._lock:
                            if fix.speed_kmh is None:
                                fix.speed_kmh = self.latest.speed_kmh
                            if fix.heading is None:
                                fix.heading = self.latest.heading
                            if not fix.satellites:
                                fix.satellites = self.latest.satellites
                            self.latest = fix
        except Exception as exc:
            self.log_cb(f"GPS {port}: {exc}", "ERROR")

    def _windows_loop(self, stop_event: threading.Event) -> None:
        self.log_cb("Solicitando ubicacion al sensor de Windows.", "INFO")
        ps = (
            "Add-Type -AssemblyName System.Device;"
            "$w=New-Object System.Device.Location.GeoCoordinateWatcher;"
            "$w.Start();$sw=[Diagnostics.Stopwatch]::StartNew();"
            "while($w.Position.Location.IsUnknown -and $sw.Elapsed.TotalSeconds -lt 8){"
            "Start-Sleep -Milliseconds 250};$c=$w.Position.Location;"
            "if(-not $c.IsUnknown){[PSCustomObject]@{latitude=$c.Latitude;longitude=$c.Longitude;"
            "altitude=$c.Altitude;accuracy=$c.HorizontalAccuracy}|ConvertTo-Json -Compress};$w.Stop()"
        )
        while not stop_event.is_set():
            try:
                result = run_console(["powershell", "-NoProfile", "-Command", ps], timeout=12)
                if result.stdout.strip():
                    data = json.loads(result.stdout.strip().splitlines()[-1])
                    fix = GPSFix(
                        latitude=float(data["latitude"]), longitude=float(data["longitude"]),
                        altitude=float(data.get("altitude", 0.0)),
                        accuracy=float(data.get("accuracy", 0.0)), source="Windows Location",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    )
                    if not stop_event.is_set():
                        with self._lock:
                            self.latest = fix
                elif not self.latest.valid:
                    self.log_cb("Windows aun no entrega coordenadas; verifica Servicios de ubicacion.", "WARNING")
            except Exception as exc:
                self.log_cb(f"Windows Location: {exc}", "ERROR")
            stop_event.wait(5.0)


class WardriveStore:
    """SQLite evidence store used by live wardriving and all export formats."""

    def __init__(self, path: Path = WARDRIVE_DB) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    gps_source TEXT NOT NULL,
                    adapter TEXT NOT NULL,
                    notes TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS observations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    ssid TEXT,
                    auth TEXT,
                    cipher TEXT,
                    channel TEXT,
                    radio TEXT,
                    signal_percent INTEGER,
                    rssi INTEGER,
                    latitude REAL,
                    longitude REAL,
                    altitude REAL,
                    accuracy REAL,
                    gps_source TEXT,
                    adapter TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
                CREATE INDEX IF NOT EXISTS idx_observations_session ON observations(session_id);
                CREATE INDEX IF NOT EXISTS idx_observations_bssid ON observations(bssid);
                """
            )
            db.commit()

    def begin_session(self, gps_source: str, adapter: str) -> int:
        with closing(self._connect()) as db:
            cur = db.execute(
                "INSERT INTO sessions(started_at,gps_source,adapter) VALUES(?,?,?)",
                (datetime.datetime.now(datetime.timezone.utc).isoformat(), gps_source, adapter),
            )
            db.commit()
            return int(cur.lastrowid)

    def end_session(self, session_id: int) -> None:
        with closing(self._connect()) as db:
            db.execute(
                "UPDATE sessions SET ended_at=? WHERE id=?",
                (datetime.datetime.now(datetime.timezone.utc).isoformat(), session_id),
            )
            db.commit()

    def add_observation(self, session_id: int, network: NetworkEntry,
                        fix: GPSFix, adapter: str) -> None:
        self.add_observations(session_id, [network], fix, adapter)

    def add_observations(self, session_id: int, networks: List[NetworkEntry],
                         fix: GPSFix, adapter: str) -> None:
        observed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        rows = [
            (
                session_id, observed_at, network.bssid, network.ssid, network.auth,
                network.cipher, network.channel, network.radio,
                parse_signal_percent(network.signal), signal_dbm(network.signal),
                fix.latitude, fix.longitude, fix.altitude, fix.accuracy, fix.source, adapter,
            )
            for network in networks if network.bssid
        ]
        if not rows:
            return
        with closing(self._connect()) as db:
            db.executemany(
                """
                INSERT INTO observations(
                    session_id,observed_at,bssid,ssid,auth,cipher,channel,radio,
                    signal_percent,rssi,latitude,longitude,altitude,accuracy,gps_source,adapter
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                rows,
            )
            db.commit()

    def session_rows(self, session_id: int) -> List[sqlite3.Row]:
        with closing(self._connect()) as db:
            return list(db.execute(
                "SELECT * FROM observations WHERE session_id=? ORDER BY observed_at,id", (session_id,)
            ))

    def best_networks(self, session_id: int) -> List[sqlite3.Row]:
        rows = self.session_rows(session_id)
        best: Dict[str, sqlite3.Row] = {}
        for row in rows:
            previous = best.get(row["bssid"])
            if previous is None or int(row["signal_percent"] or 0) > int(previous["signal_percent"] or 0):
                best[row["bssid"]] = row
        return sorted(best.values(), key=lambda item: int(item["signal_percent"] or 0), reverse=True)

    def counts(self, session_id: int) -> Tuple[int, int]:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT COUNT(*) total, COUNT(DISTINCT bssid) networks FROM observations WHERE session_id=?",
                (session_id,),
            ).fetchone()
            return int(row["networks"]), int(row["total"])


class WardriveExporter:
    @staticmethod
    def _basename(session_id: int) -> str:
        return f"wardrive_{session_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    @staticmethod
    def export_all(store: WardriveStore, session_id: int) -> Dict[str, Path]:
        EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
        base = WardriveExporter._basename(session_id)
        rows = store.session_rows(session_id)
        best = store.best_networks(session_id)
        outputs = {
            "wigle": EXPORTS_DIR / f"{base}_wigle.csv",
            "geojson": EXPORTS_DIR / f"{base}.geojson",
            "kml": EXPORTS_DIR / f"{base}.kml",
            "html": EXPORTS_DIR / f"{base}_mapa.html",
        }
        WardriveExporter._write_wigle(outputs["wigle"], rows)
        features = WardriveExporter._features(best)
        outputs["geojson"].write_text(
            json.dumps({"type": "FeatureCollection", "features": features}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        WardriveExporter._write_kml(outputs["kml"], features)
        WardriveExporter._write_html(outputs["html"], features, session_id)
        return outputs

    @staticmethod
    def _write_wigle(path: Path, rows: List[sqlite3.Row]) -> None:
        with path.open("w", encoding="utf-8", newline="") as fh:
            fh.write(
                f"WigleWifi-1.4,appRelease={VERSION},model={platform.machine()},"
                f"release={platform.release()},device=WirelessAuditPro,display=GUI,board=Windows,brand=Roger\n"
            )
            writer = csv.writer(fh)
            writer.writerow([
                "MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
                "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
                "AccuracyMeters", "Type",
            ])
            for row in rows:
                if row["latitude"] is None or row["longitude"] is None:
                    continue
                writer.writerow([
                    row["bssid"], row["ssid"], auth_mode(row["auth"], row["cipher"]),
                    row["observed_at"].replace("T", " ")[:19], row["channel"], row["rssi"],
                    row["latitude"], row["longitude"], row["altitude"] or 0,
                    row["accuracy"] or 0, "WIFI",
                ])

    @staticmethod
    def _features(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
        features: List[Dict[str, Any]] = []
        for row in rows:
            if row["latitude"] is None or row["longitude"] is None:
                continue
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [row["longitude"], row["latitude"]]},
                "properties": {
                    "ssid": row["ssid"], "bssid": row["bssid"], "auth": row["auth"],
                    "cipher": row["cipher"], "channel": row["channel"], "rssi": row["rssi"],
                    "signal": row["signal_percent"], "observed_at": row["observed_at"],
                },
            })
        return features

    @staticmethod
    def _write_kml(path: Path, features: List[Dict[str, Any]]) -> None:
        placemarks = []
        for feature in features:
            prop = feature["properties"]
            lon, lat = feature["geometry"]["coordinates"]
            placemarks.append(
                "<Placemark><name>" + xml_escape(str(prop.get("ssid") or "SSID oculto")) + "</name>"
                "<description>" + xml_escape(
                    f"BSSID: {prop['bssid']} | {prop['auth']} | CH {prop['channel']} | RSSI {prop['rssi']} dBm"
                ) + "</description><Point><coordinates>" + f"{lon},{lat},0" +
                "</coordinates></Point></Placemark>"
            )
        body = "<?xml version='1.0' encoding='UTF-8'?><kml xmlns='http://www.opengis.net/kml/2.2'><Document>" + "".join(placemarks) + "</Document></kml>"
        path.write_text(body, encoding="utf-8")

    @staticmethod
    def _write_html(path: Path, features: List[Dict[str, Any]], session_id: int) -> None:
        points = json.dumps(features, ensure_ascii=False).replace("</", "<\\/")
        page = f"""<!doctype html><html lang='es'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'><title>Wardrive {session_id}</title>
<link rel='stylesheet' href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'>
<style>html,body,#map{{height:100%;margin:0;background:#06100a}}.badge{{position:absolute;z-index:9999;left:14px;top:14px;background:#07150ddd;color:#6cff87;padding:12px 16px;border:1px solid #36a94e;border-radius:9px;font:13px Consolas}}</style></head>
<body><div id='map'></div><div class='badge'>Wireless Audit Pro · Wardrive {session_id}<br>Redes geolocalizadas: {len(features)}</div>
<script src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js'></script><script>
const features={points}; const map=L.map('map').setView([14.6349,-90.5069],13);
L.tileLayer('https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{maxZoom:19,attribution:'OpenStreetMap'}}).addTo(map);
const bounds=[]; for(const f of features){{const [lon,lat]=f.geometry.coordinates; const p=f.properties;
const color=(p.auth||'').toUpperCase().includes('OPEN')?'#ff5964':'#54ff72';
L.circleMarker([lat,lon],{{radius:7,color,fillColor:color,fillOpacity:.75}}).bindPopup(`<b>${{p.ssid||'SSID oculto'}}</b><br>${{p.bssid}}<br>${{p.auth}} · CH ${{p.channel}}<br>RSSI ${{p.rssi}} dBm`).addTo(map);bounds.push([lat,lon]);}}
if(bounds.length)map.fitBounds(bounds,{{padding:[30,30]}});</script></body></html>"""
        path.write_text(page, encoding="utf-8")


@dataclass
class CapabilitySnapshot:
    active_adapter: str = "Desconocido"
    monitor_advertised: bool = False
    npcap_dot11: bool = False
    capture_linktypes: str = "N/A"
    alfa_present: bool = False
    alfa_registered: bool = False
    alfa_usb_state: str = "No conectada"
    alfa_hardware_id: str = "0bda:8813"
    alfa_module_ready: bool = False
    alfa_linux_interface: str = ""
    alfa_windows_interface: str = ""
    alfa_windows_description: str = ""
    alfa_windows_mac: str = ""
    alfa_windows_driver: str = ""
    alfa_native_scan: bool = False
    wsl_available: bool = False
    kali_state: str = "No disponible"
    notes: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = []


class CapabilityEngine:
    @staticmethod
    def _usbipd_sections(output: str) -> Tuple[str, str]:
        """Separate physically connected USB devices from persisted registrations."""
        connected: List[str] = []
        persisted: List[str] = []
        section = ""
        for line in output.splitlines():
            heading = line.strip().casefold()
            if heading == "connected:":
                section = "connected"
                continue
            if heading == "persisted:":
                section = "persisted"
                continue
            if section == "connected":
                connected.append(line)
            elif section == "persisted":
                persisted.append(line)
        return "\n".join(connected), "\n".join(persisted)

    @staticmethod
    def probe(active_adapter: str, force: bool = False) -> CapabilitySnapshot:
        result = CapabilitySnapshot(active_adapter=active_adapter)
        drivers = ""
        if os.name != "nt":
            try:
                interfaces = [
                    item for item in AlfaWslCore.list_interfaces()
                    if re.fullmatch(r"[A-Za-z0-9_.-]+", item)
                ]
                usb = AlfaWslCore.status()
                result.alfa_present = any(
                    token in usb.lower() for token in (*AlfaWslCore.HARDWARE_IDS, "8814au", "awus1900")
                )
                result.alfa_registered = result.alfa_present
                result.alfa_usb_state = next(
                    (line.strip() for line in usb.splitlines()
                     if any(token in line.lower() for token in (*AlfaWslCore.HARDWARE_IDS, "8814au"))),
                    "USB no detectado",
                )
                result.alfa_linux_interface = interfaces[0] if interfaces else ""
                result.alfa_module_ready = run_console(
                    AlfaWslCore._shell("modinfo 8814au >/dev/null 2>&1 || test -r /opt/wireless-audit/8814au.ko"),
                    timeout=10,
                ).returncode == 0
                iw_list = run_console(AlfaWslCore._shell("iw list 2>/dev/null"), timeout=15).stdout
                result.monitor_advertised = "* monitor" in iw_list.lower()
                result.wsl_available = False
                result.kali_state = "Kali / Linux nativo"
                result.alfa_native_scan = bool(interfaces)
            except Exception as exc:
                result.notes.append(f"Linux RF: {exc}")
            return result

        try:
            drivers = run_console(["netsh", "wlan", "show", "drivers"], timeout=12).stdout
            monitor = re.search(r"Monitor inal[aá]mbrico admitido\s*:\s*(S[ií]|Yes)", drivers, re.IGNORECASE)
            result.monitor_advertised = bool(monitor)
        except Exception as exc:
            result.notes.append(f"netsh drivers: {exc}")

        tshark = find_tool_binary("tshark")
        if tshark:
            try:
                listing = run_console([tshark, "-D"], timeout=10).stdout
                index = ""
                for line in listing.splitlines():
                    if f"({active_adapter})".lower() in line.lower():
                        match = re.match(r"\s*(\d+)\.", line)
                        index = match.group(1) if match else ""
                        break
                if index:
                    links = run_console([tshark, "-i", index, "-L"], timeout=12).stdout
                    result.capture_linktypes = " | ".join(
                        line.strip() for line in links.splitlines() if line.strip() and "Data link" not in line
                    ) or "No expuestos"
                    upper = links.upper()
                    result.npcap_dot11 = "IEEE802_11" in upper or "RADIOTAP" in upper
            except Exception as exc:
                result.notes.append(f"Npcap/TShark: {exc}")
        else:
            result.notes.append("TShark no instalado")

        try:
            usb = run_console(["usbipd", "list"], timeout=10).stdout
            connected_usb, persisted_usb = CapabilityEngine._usbipd_sections(usb)
            for line in connected_usb.splitlines():
                lower = line.lower()
                if any(token in lower for token in (
                    "0bda:8813", "0bda:881a", "realtek 8814", "rtl8814", "awus1900",
                )):
                    result.alfa_present = True
                    result.alfa_registered = True
                    result.alfa_usb_state = line.strip()
                    break
            if not result.alfa_registered and any(
                token in persisted_usb.lower()
                for token in ("realtek 8814", "rtl8814", "awus1900")
            ):
                result.alfa_registered = True
                result.alfa_usb_state = "Registrada para auto-attach; actualmente desconectada"
        except Exception:
            result.notes.append("usbipd-win no disponible")

        try:
            alfa_windows = AdapterManager.get_alfa_info(force=force)
            if alfa_windows.is_alfa:
                result.alfa_present = True
                result.alfa_registered = True
                result.alfa_windows_interface = alfa_windows.name
                result.alfa_windows_description = alfa_windows.description
                result.alfa_windows_mac = alfa_windows.mac
                result.alfa_windows_driver = alfa_windows.driver_version
                result.alfa_native_scan = True
                driver_block = re.search(
                    rf"(?:Nombre de interfaz|Interface name)\s*:\s*{re.escape(alfa_windows.name)}\s*(.*?)"
                    r"(?=\n(?:Nombre de interfaz|Interface name)\s*:|\Z)",
                    drivers, re.IGNORECASE | re.DOTALL,
                )
                if driver_block:
                    version = re.search(
                        r"(?:Versi[oó]n|Version)\s*:\s*([^\r\n]+)", driver_block.group(1), re.IGNORECASE
                    )
                    if version:
                        result.alfa_windows_driver = version.group(1).strip()
        except Exception as exc:
            result.notes.append(f"Alfa Windows: {exc}")

        try:
            wsl = run_console(["wsl.exe", "--list", "--verbose"], timeout=12).stdout
            result.wsl_available = "kali-linux" in wsl.lower()
            if result.wsl_available:
                kali_line = next((line.strip() for line in wsl.splitlines() if "kali-linux" in line.lower()), "Kali instalada")
                result.kali_state = kali_line
                if result.alfa_present and (
                    "attached" in result.alfa_usb_state.lower()
                    or "adjunt" in result.alfa_usb_state.lower()
                ):
                    rf_probe = run_console([
                        "wsl.exe", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc",
                        "if modinfo 8814au >/dev/null 2>&1 || "
                        "test -r /opt/wireless-audit/8814au.ko; then echo MODULE_READY; fi; "
                        "iw dev 2>/dev/null",
                    ], timeout=15)
                    result.alfa_module_ready = "MODULE_READY" in rf_probe.stdout
                    match = re.search(r"^\s*Interface\s+(\S+)", rf_probe.stdout, re.MULTILINE)
                    result.alfa_linux_interface = match.group(1) if match else ""
                    result.alfa_native_scan = result.alfa_native_scan or bool(result.alfa_linux_interface)
                    refreshed_wsl = run_console(["wsl.exe", "--list", "--verbose"], timeout=12).stdout
                    result.kali_state = next(
                        (line.strip() for line in refreshed_wsl.splitlines()
                         if "kali-linux" in line.lower()),
                        result.kali_state,
                    )
        except Exception as exc:
            result.notes.append(f"WSL: {exc}")
        return result


class AlfaWslCore:
    HARDWARE_IDS = ("0bda:8813", "0bda:881a")
    DRIVER_PATH = "/opt/wireless-audit/8814au.ko"
    COUNTRY_CODE = "GT"

    @staticmethod
    def _shell(script: str, root: bool = True) -> List[str]:
        """Run the same RF operation in Kali WSL2 or on native Linux."""
        if os.name == "nt":
            prefix = ["wsl.exe", "-d", "kali-linux"]
            if root:
                prefix.extend(["-u", "root"])
            return prefix + ["--", "bash", "-lc", script]
        if root and hasattr(os, "geteuid") and os.geteuid() != 0:
            return ["sudo", "-n", "bash", "-lc", script]
        return ["bash", "-lc", script]

    @staticmethod
    def status() -> str:
        try:
            if os.name == "nt":
                return run_console(["usbipd", "list"], timeout=10).stdout
            return run_console(["lsusb"], timeout=10).stdout
        except Exception as exc:
            return f"USB: {exc}"

    @staticmethod
    def attach(log_cb: Any) -> bool:
        if os.name != "nt":
            interfaces = [
                item for item in AlfaWslCore.list_interfaces()
                if re.fullmatch(r"[A-Za-z0-9_.-]+", item)
            ]
            if not interfaces:
                AlfaWslCore._activate_driver(log_cb)
                interfaces = [
                    item for item in AlfaWslCore.list_interfaces()
                    if re.fullmatch(r"[A-Za-z0-9_.-]+", item)
                ]
            log_cb(
                f"[ALFA] Linux nativo listo: {', '.join(interfaces)}" if interfaces
                else "[ALFA] USB presente pero sin interfaz nl80211.",
                "OK" if interfaces else "ERROR",
            )
            return bool(interfaces)
        listing = AlfaWslCore.status()
        hardware_id = next((item for item in AlfaWslCore.HARDWARE_IDS if item in listing.lower()), "")
        if not hardware_id:
            log_cb("Alfa AWUS1900 no conectada por USB.", "ERROR")
            return False
        cmd = ["usbipd", "attach", "--wsl", "kali-linux", "--hardware-id", hardware_id]
        try:
            # usbipd cannot attach to a stopped distribution. Starting it with
            # a no-op is silent and avoids a misleading first-click failure.
            run_console(["wsl.exe", "-d", "kali-linux", "--", "true"], timeout=25)
            result = run_console(cmd, timeout=30)
            text_out = (result.stdout + "\n" + result.stderr).strip()
            if result.returncode == 0:
                log_cb("[USBIPD] " + (text_out or "Alfa adjunta a Kali."), "OK")
                AlfaWslCore._activate_driver(log_cb)
                return True
            lower = text_out.lower()
            if "not shared" in lower or "bind" in lower or "no está compartido" in lower:
                log_cb("[USBIPD] Registrando el dispositivo; Windows solicitará elevación UAC.", "WARNING")
                ps = (
                    "Start-Process -FilePath 'usbipd' -Verb RunAs -Wait -ArgumentList "
                    f"@('bind','--force','--hardware-id','{hardware_id}')"
                )
                bound = run_console(["powershell", "-NoProfile", "-Command", ps], timeout=90)
                if bound.returncode == 0:
                    retry = run_console(cmd, timeout=30)
                    retry_text = (retry.stdout + "\n" + retry.stderr).strip()
                    log_cb("[USBIPD] " + (retry_text or "Alfa adjunta a Kali."),
                           "OK" if retry.returncode == 0 else "ERROR")
                    if retry.returncode == 0:
                        AlfaWslCore._activate_driver(log_cb)
                    return retry.returncode == 0
            log_cb("[USBIPD] " + text_out, "ERROR")
            return False
        except Exception as exc:
            log_cb(f"[USBIPD] {exc}", "ERROR")
            return False

    @staticmethod
    def _activate_driver(log_cb: Any) -> None:
        time.sleep(1.2)
        country = AlfaWslCore.COUNTRY_CODE
        driver = AlfaWslCore.DRIVER_PATH
        script = (
            "if ! lsmod | grep -q '^8814au '; then "
            "modprobe 8814au >/dev/null 2>&1 || { "
            "modprobe usbcore; modprobe cfg80211; "
            f"insmod {driver} rtw_country_code={country}; }}; fi; "
            "sleep 2; "
            f"iw reg set {country} 2>/dev/null || true; "
            "iface=$(iw dev 2>/dev/null | sed -n 's/^[[:space:]]*Interface[[:space:]]\\+//p' | head -n1); "
            "if [ -n \"$iface\" ]; then ip link set \"$iface\" up 2>/dev/null || true; "
            "iw dev \"$iface\" set power_save off 2>/dev/null || true; "
            "iw dev \"$iface\" set txpower auto 2>/dev/null || true; fi; "
            "iw dev 2>&1"
        )
        result = run_console(AlfaWslCore._shell(script), timeout=20)
        output = (result.stdout + "\n" + result.stderr).strip()
        if output:
            for line in output.splitlines():
                log_cb("[ALFA] " + line, "INFO")
        interfaces = re.findall(r"Interface\s+(\S+)", output)
        if interfaces:
            run_console(AlfaWslCore._shell(f"ip link set {interfaces[0]} up"), timeout=10)
            log_cb(f"[ALFA] Radio nl80211 lista: {', '.join(interfaces)}", "OK")
        else:
            log_cb("[ALFA] USB adjunto, pero todavía no existe interfaz nl80211.", "WARNING")

    @staticmethod
    def ensure_ready(log_cb: Any) -> bool:
        interfaces = [
            item for item in AlfaWslCore.list_interfaces()
            if re.fullmatch(r"[A-Za-z0-9_.-]+", item)
        ]
        if interfaces:
            return True
        if os.name != "nt":
            return AlfaWslCore.attach(log_cb)
        listing = AlfaWslCore.status()
        device_line = next(
            (line for line in listing.splitlines()
             if any(hardware_id in line.lower() for hardware_id in AlfaWslCore.HARDWARE_IDS)),
            "",
        )
        state = device_line.lower()
        if "attached" in state or "adjunt" in state:
            AlfaWslCore._activate_driver(log_cb)
        elif "shared" in state or "compart" in state:
            AlfaWslCore.attach(log_cb)
        else:
            return False
        return any(
            re.fullmatch(r"[A-Za-z0-9_.-]+", item)
            for item in AlfaWslCore.list_interfaces()
        )

    @staticmethod
    def set_reg_domain(country_code: str, log_cb: Any) -> bool:
        code = country_code.strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", code):
            log_cb("[ALFA] El dominio RF debe ser un código ISO de dos letras.", "ERROR")
            return False
        AlfaWslCore.COUNTRY_CODE = code
        driver = AlfaWslCore.DRIVER_PATH
        script = (
            "for iface in $(iw dev 2>/dev/null | sed -n 's/^[[:space:]]*Interface[[:space:]]\\+//p'); do "
            "ip link set \"$iface\" down 2>/dev/null || true; done; "
            "if lsmod | grep -q '^8814au '; then rmmod 8814au || exit 3; fi; "
            "modprobe usbcore; modprobe cfg80211; "
            f"modprobe 8814au rtw_country_code={code} >/dev/null 2>&1 || "
            f"insmod {driver} rtw_country_code={code} || exit 4; "
            "sleep 2; "
            f"iw reg set {code} 2>/dev/null || true; "
            "iface=$(iw dev 2>/dev/null | sed -n 's/^[[:space:]]*Interface[[:space:]]\\+//p' | head -n1); "
            "if [ -n \"$iface\" ]; then ip link set \"$iface\" up 2>/dev/null || true; "
            "iw dev \"$iface\" set power_save off 2>/dev/null || true; "
            "iw dev \"$iface\" set txpower auto 2>/dev/null || true; fi; "
            "printf 'DRIVER_COUNTRY:'; cat /sys/module/8814au/parameters/rtw_country_code; "
            "iw dev; iw reg get"
        )
        result = run_console(AlfaWslCore._shell(script), timeout=20)
        output = (result.stdout + "\n" + result.stderr).strip()
        for line in output.splitlines()[:30]:
            log_cb("[REG] " + line, "INFO")
        interfaces = re.findall(r"Interface\s+(\S+)", output)
        if interfaces:
            run_console(AlfaWslCore._shell(f"ip link set {interfaces[0]} up"), timeout=10)
        ok = result.returncode == 0 and f"DRIVER_COUNTRY:{code}" in output and bool(interfaces)
        log_cb(
            f"[ALFA] Perfil regulatorio {code} cargado en el driver." if ok
            else f"[ALFA] No se confirmó el perfil regulatorio {code}.",
            "OK" if ok else "WARNING",
        )
        return ok

    @staticmethod
    def detach(log_cb: Any) -> bool:
        if os.name != "nt":
            log_cb("En Linux nativo la Alfa no usa puente USB/IP.", "INFO")
            return True
        listing = AlfaWslCore.status()
        hardware_id = next((item for item in AlfaWslCore.HARDWARE_IDS if item in listing.lower()), "")
        if not hardware_id:
            log_cb("No se encontro hardware Alfa para separar.", "WARNING")
            return False
        try:
            result = run_console(["usbipd", "detach", "--hardware-id", hardware_id], timeout=20)
            log_cb((result.stdout or result.stderr).strip() or "Alfa separada de WSL.",
                   "OK" if result.returncode == 0 else "ERROR")
            return result.returncode == 0
        except Exception as exc:
            log_cb(str(exc), "ERROR")
            return False

    @staticmethod
    def linux_probe(log_cb: Any) -> Dict[str, Any]:
        script = (
            "printf '=== USB ===\\n'; lsusb 2>&1; printf '\\n=== IW ===\\n'; iw dev 2>&1; "
            "printf '\\n=== TOOLS ===\\n'; for t in iw airmon-ng airodump-ng aireplay-ng aircrack-ng "
            "hcxdumptool hcxpcapngtool tshark hashcat wifite; do printf '%s: ' \"\\$t\"; "
            "command -v \"\\$t\" || echo FALTA; done; "
            "printf '\\n=== DRIVER RTL8814AU ===\\n'; uname -r; dkms status 2>&1; "
            "if modinfo 8814au >/dev/null 2>&1 || test -r /opt/wireless-audit/8814au.ko; "
            "then echo 'MODULE: LISTO'; "
            "else echo 'MODULE: NO COMPILADO PARA ESTE KERNEL'; fi"
        )
        try:
            result = run_console(AlfaWslCore._shell(script), timeout=35)
            output = (result.stdout + "\n" + result.stderr).strip()
            for line in output.splitlines():
                log_cb(line, "INFO")
            interfaces = re.findall(r"Interface\s+(\S+)", output)
            module_ready = "MODULE: LISTO" in output
            ok = result.returncode == 0 and "Error interno" not in output and "command not found" not in output
            return {
                "ok": ok, "output": output, "interfaces": interfaces,
                "module_ready": module_ready,
            }
        except Exception as exc:
            log_cb(f"Kali WSL: {exc}", "ERROR")
            return {"ok": False, "output": str(exc), "interfaces": [], "module_ready": False}

    @staticmethod
    def install_toolchain(log_cb: Any) -> bool:
        packages = (
            "iw wireless-tools aircrack-ng hcxdumptool hcxtools tshark hashcat wifite usbutils "
            "pciutils realtek-rtl8814au-dkms"
        )
        script = (
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update && apt-get install -y " + packages + "; "
            "release=$(uname -r); "
            "if [ -f /lib/modules/$release/build/Makefile ]; then "
            "dkms autoinstall -k $release || true; depmod -a $release; fi"
        )
        cmd = AlfaWslCore._shell(script)
        log_cb("[KALI] Instalando toolchain wireless…", "INFO")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                **hidden_process_kwargs(),
            )
            if proc.stdout:
                for raw in iter(proc.stdout.readline, b""):
                    line = decode_console_bytes(raw).strip()
                    if line:
                        log_cb("[APT] " + line, "INFO")
            code = proc.wait()
            log_cb("[KALI] Toolchain instalado." if code == 0 else f"[KALI] APT terminó con código {code}.",
                   "OK" if code == 0 else "ERROR")
            if code == 0:
                AlfaWslCore._activate_driver(log_cb)
            return code == 0
        except Exception as exc:
            log_cb(f"[KALI] Instalación: {exc}", "ERROR")
            return False

    @staticmethod
    def validate_monitor_injection(log_cb: Any) -> bool:
        interfaces = [item for item in AlfaWslCore.list_interfaces() if re.fullmatch(r"[A-Za-z0-9_.-]+", item)]
        if not interfaces:
            log_cb("[KALI] No hay interfaz wireless adjunta.", "ERROR")
            return False
        interface = interfaces[0]
        log_cb(f"[KALI] Preparando monitor sobre {interface}…", "INFO")
        monitor = ""
        try:
            prep_script = f"airmon-ng check kill; airmon-ng start {interface}; iw dev"
            prep = run_console(AlfaWslCore._shell(prep_script), timeout=45)
            output = (prep.stdout + "\n" + prep.stderr).strip()
            for line in output.splitlines():
                log_cb("[MONITOR] " + line, "INFO")
            blocks = re.findall(r"Interface\s+(\S+)(.*?)(?=\n\s*Interface\s+|\Z)", output, re.DOTALL)
            monitor = next((name for name, block in blocks if "type monitor" in block), "")
            if not monitor:
                current = run_console(AlfaWslCore._shell("iw dev", root=False), timeout=15).stdout
                blocks = re.findall(r"Interface\s+(\S+)(.*?)(?=\n\s*Interface\s+|\Z)", current, re.DOTALL)
                monitor = next((name for name, block in blocks if "type monitor" in block), "")
            if not monitor:
                log_cb("[KALI] El driver no creó una interfaz monitor.", "ERROR")
                return False
            test = run_console(
                AlfaWslCore._shell(f"timeout 20 aireplay-ng --test {monitor}"), timeout=30
            )
            test_output = (test.stdout + "\n" + test.stderr).strip()
            for line in test_output.splitlines():
                log_cb("[INJECTION] " + line, "INFO")
            ok = "injection is working" in test_output.lower() or (
                test.returncode == 0 and "no such device" not in test_output.lower()
            )
            log_cb("Monitor e inyección validados." if ok else "La prueba de inyección no fue concluyente.",
                   "OK" if ok else "WARNING")
            return ok
        except Exception as exc:
            log_cb(f"[KALI] Validación monitor: {exc}", "ERROR")
            return False
        finally:
            cleanup = f"airmon-ng stop {monitor} 2>/dev/null || true; service NetworkManager start 2>/dev/null || true"
            try:
                run_console(AlfaWslCore._shell(cleanup), timeout=25)
            except Exception:
                pass

    @staticmethod
    def list_interfaces() -> List[str]:
        try:
            result = run_console(
                AlfaWslCore._shell(
                    "iw dev 2>/dev/null | awk '$1==\"Interface\"{print $2}'", root=False
                ), timeout=20
            )
            interfaces = [line.strip() for line in result.stdout.splitlines() if re.fullmatch(r"[A-Za-z0-9_.-]+", line.strip())]
            return interfaces or ["Sin interfaz Wi-Fi en Kali"]
        except Exception as exc:
            return [f"Error Kali: {exc}"]

    @staticmethod
    def scan_networks() -> List["NetworkEntry"]:
        """Scan through the physical Alfa/nl80211 radio exposed to Kali."""
        interfaces = [
            item for item in AlfaWslCore.list_interfaces()
            if re.fullmatch(r"[A-Za-z0-9_.-]+", item)
        ]
        if not interfaces:
            return []
        interface = interfaces[0]
        with WLAN_SCAN_LOCK:
            for attempt in range(2):
                result = run_console(
                    AlfaWslCore._shell(
                        f"ip link set {interface} up; sleep 1; iw dev {interface} scan"
                    ), timeout=35
                )
                if result.returncode == 0 and result.stdout.strip():
                    return AlfaWslCore._parse_iw_scan(result.stdout)
                if attempt == 0:
                    time.sleep(1.0)
        return []

    @staticmethod
    def _frequency_channel(frequency: int) -> int:
        if frequency == 2484:
            return 14
        if 2412 <= frequency <= 2472:
            return (frequency - 2407) // 5
        if 4915 <= frequency <= 5895:
            return (frequency - 5000) // 5
        if frequency == 5935:
            return 2
        if 5955 <= frequency <= 7115:
            return (frequency - 5950) // 5
        return 0

    @staticmethod
    def _parse_iw_scan(data: str) -> List["NetworkEntry"]:
        networks: List[NetworkEntry] = []
        blocks = re.split(r"(?m)(?=^BSS\s+[0-9a-fA-F:]{17})", data)
        for block in blocks:
            bssid_match = re.match(r"BSS\s+([0-9a-fA-F:]{17})", block.strip())
            if not bssid_match:
                continue
            bssid = bssid_match.group(1).upper()
            ssid_match = re.search(r"(?m)^\s*SSID:\s*(.*)$", block)
            raw_ssid = ssid_match.group(1).strip() if ssid_match else ""
            ssid = raw_ssid or "<SSID Oculto>"
            frequency_match = re.search(r"(?m)^\s*freq:\s*(\d+)", block)
            frequency = int(frequency_match.group(1)) if frequency_match else 0
            channel = AlfaWslCore._frequency_channel(frequency)
            signal_match = re.search(r"(?m)^\s*signal:\s*(-?\d+(?:\.\d+)?)\s*dBm", block)
            dbm = float(signal_match.group(1)) if signal_match else -100.0
            percent = max(0, min(100, round(2 * (dbm + 100))))

            upper = block.upper()
            privacy = bool(re.search(r"(?mi)^\s*CAPABILITY:.*PRIVACY", block))
            if "RSN:" in upper:
                if "AUTHENTICATION SUITES: SAE" in upper and "PSK" in upper:
                    auth = "WPA2/WPA3-Personal"
                elif "AUTHENTICATION SUITES: SAE" in upper:
                    auth = "WPA3-Personal"
                elif "802.1X" in upper:
                    auth = "WPA2-Enterprise"
                else:
                    auth = "WPA2-Personal"
            elif "WPA:" in upper:
                auth = "WPA-Enterprise" if "802.1X" in upper else "WPA-Personal"
            elif privacy:
                auth = "WEP"
            else:
                auth = "Open"

            cipher_match = re.search(r"(?mi)^\s*\*?\s*PAIRWISE CIPHERS?:\s*(.+)$", block)
            cipher = cipher_match.group(1).strip() if cipher_match else (
                "WEP" if auth == "WEP" else "Ninguno" if auth == "Open" else "Desconocido"
            )
            if "HE CAPABILITIES" in upper:
                radio = "802.11ax"
            elif "VHT CAPABILITIES" in upper:
                radio = "802.11ac"
            elif "HT CAPABILITIES" in upper:
                radio = "802.11n"
            else:
                radio = "802.11a" if frequency >= 4900 else "802.11g"
            rates_match = re.search(r"(?mi)^\s*SUPPORTED RATES:\s*(.+)$", block)
            score, label, recommendation = security_score(auth, cipher)
            networks.append(NetworkEntry(
                ssid=ssid, bssid=bssid, vendor=get_vendor(bssid),
                signal=f"{percent}% ({dbm:.0f} dBm)", radio=radio,
                channel=str(channel or ""), frequency_mhz=frequency, auth=auth, cipher=cipher,
                rates=rates_match.group(1).strip() if rates_match else "",
                score=score, score_label=label, recommendation=recommendation,
                hidden=not bool(raw_ssid),
            ))
        return networks

    @staticmethod
    def _wsl_path(path: Path) -> str:
        resolved = path.resolve()
        drive = resolved.drive.rstrip(":").lower()
        tail = resolved.as_posix().split(":", 1)[-1]
        return f"/mnt/{drive}{tail}"

    @staticmethod
    def capture(interface: str, output_file: Path, timeout_sec: int,
                stop_event: threading.Event, log_cb: Any) -> bool:
        iface = re.sub(r"[^A-Za-z0-9_.-]", "", interface)
        if not iface:
            log_cb("[KALI] Interfaz no valida.", "ERROR")
            return False
        output_file.parent.mkdir(parents=True, exist_ok=True)
        linux_output = AlfaWslCore._wsl_path(output_file)
        script = (
            "if command -v hcxdumptool >/dev/null 2>&1; then "
            f"sudo -n timeout --signal=INT {int(timeout_sec)} hcxdumptool -i {iface} -w '{linux_output}'; "
            "else echo 'FALTA hcxdumptool' >&2; exit 127; fi"
        )
        cmd = ["wsl.exe", "-d", "kali-linux", "--", "bash", "-lc", script]
        log_cb(f"[KALI] hcxdumptool · {iface} · {timeout_sec}s", "INFO")
        try:
            with tempfile.TemporaryFile() as output_stream:
                proc = subprocess.Popen(
                    cmd, stdout=output_stream, stderr=subprocess.STDOUT,
                    **hidden_process_kwargs(),
                )
                while proc.poll() is None:
                    if stop_event.is_set():
                        proc.terminate()
                        run_console([
                            "wsl.exe", "-d", "kali-linux", "--", "bash", "-lc",
                            "sudo -n pkill -INT hcxdumptool 2>/dev/null || true",
                        ], timeout=8)
                        log_cb("[KALI] Captura detenida.", "WARNING")
                        return False
                    time.sleep(0.4)
                output_stream.seek(0)
                output_lines = decode_console_bytes(output_stream.read()).splitlines()
            for line in output_lines[-30:]:
                if line.strip():
                    log_cb("[KALI] " + line.strip(), "INFO")
            valid = output_file.exists() and output_file.stat().st_size > 64
            log_cb(
                f"[KALI] Evidencia: {output_file}" if valid else "[KALI] No se generó PCAPNG válido.",
                "OK" if valid else "ERROR",
            )
            return valid
        except Exception as exc:
            log_cb(f"[KALI] {exc}", "ERROR")
            return False


class WifiteCore:
    """Native Linux runner with a Windows-to-Kali WSL bridge."""

    MODES = {
        "WPA/WPA2": ["--wpa"],
        "WPS": ["--wps"],
        "PMKID": ["--pmkid"],
        "WPA3": ["--wpa3"],
        "Todos": [],
    }

    @staticmethod
    def engine_name() -> str:
        return "Windows -> Kali WSL2" if os.name == "nt" else "Linux nativo"

    @staticmethod
    def _prefix() -> List[str]:
        if os.name == "nt":
            return [
                "wsl.exe", "-d", "kali-linux", "-u", "root", "--",
                "env", "TERM=dumb", "PYTHONUNBUFFERED=1",
            ]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return ["env", "TERM=dumb", "PYTHONUNBUFFERED=1"]
        return ["sudo", "-n", "env", "TERM=dumb", "PYTHONUNBUFFERED=1"]

    @staticmethod
    def probe() -> Tuple[bool, str]:
        try:
            cmd = WifiteCore._prefix() + ["wifite", "-h"]
            result = run_console(cmd, timeout=20)
            output = strip_ansi(result.stdout + "\n" + result.stderr)
            version = re.search(r"wifite2\s+([0-9.]+)", output, re.IGNORECASE)
            if result.returncode == 0 and version:
                return True, f"Wifite {version.group(1)} | {WifiteCore.engine_name()}"
            return False, output.strip().splitlines()[-1] if output.strip() else "Wifite no disponible"
        except Exception as exc:
            return False, str(exc)

    @staticmethod
    def install(log_cb: Any) -> bool:
        if os.name == "nt":
            cmd = [
                "wsl.exe", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc",
                "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y wifite",
            ]
        else:
            prefix = [] if hasattr(os, "geteuid") and os.geteuid() == 0 else ["sudo", "-n"]
            cmd = prefix + ["apt-get", "install", "-y", "wifite"]
        try:
            with tempfile.TemporaryFile() as output_stream:
                proc = subprocess.Popen(
                    cmd, stdout=output_stream, stderr=subprocess.STDOUT,
                    **hidden_process_kwargs(),
                )
                while proc.poll() is None:
                    time.sleep(0.25)
                output_stream.seek(0)
                output = strip_ansi(decode_console_bytes(output_stream.read()))
            for line in output.splitlines()[-30:]:
                if line.strip():
                    log_cb(line.strip(), "INFO")
            ok = proc.returncode == 0
            log_cb("Wifite instalado/verificado." if ok else f"APT finalizó con código {proc.returncode}.",
                   "OK" if ok else "ERROR")
            return ok
        except Exception as exc:
            log_cb(str(exc), "ERROR")
            return False

    @staticmethod
    def list_interfaces() -> List[str]:
        if os.name == "nt":
            return AlfaWslCore.list_interfaces()
        try:
            result = run_console(["iw", "dev"], timeout=12)
            interfaces = re.findall(r"Interface\s+(\S+)", result.stdout)
            return interfaces or ["Sin interfaz Wi-Fi en Linux"]
        except Exception as exc:
            return [f"Error Linux: {exc}"]

    @staticmethod
    def build_args(
        interface: str,
        mode: str,
        scan_time: int,
        min_power: int,
        max_targets: int,
        bssid: str = "",
        passive: bool = True,
        kill_conflicts: bool = False,
        random_mac: bool = False,
        ignore_cracked: bool = True,
        wordlist: Optional[Path] = None,
    ) -> List[str]:
        iface = re.sub(r"[^A-Za-z0-9_.-]", "", interface)
        if not iface:
            raise ValueError("Interfaz Wi-Fi no válida")
        args = [
            "wifite", "-i", iface, "-p", str(max(10, min(600, scan_time))),
            "-pow", str(max(0, min(100, min_power))),
            "-first", str(max(1, min(50, max_targets))), "--showb", "--daemon",
        ]
        args.extend(WifiteCore.MODES.get(mode, []))
        if bssid:
            clean_bssid = re.sub(r"[^0-9A-Fa-f:]", "", bssid)[:17]
            if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", clean_bssid):
                raise ValueError("BSSID no válido")
            args.extend(["-b", clean_bssid])
        if passive:
            args.append("--nodeauths")
        if kill_conflicts:
            args.append("--kill")
        if random_mac:
            args.append("--random-mac")
        if ignore_cracked:
            args.append("--ignore-cracked")
        if wordlist:
            path_value = AlfaWslCore._wsl_path(wordlist) if os.name == "nt" else str(wordlist)
            args.extend(["--dict", path_value])
        return args

    @staticmethod
    def run(args: List[str], stop_event: threading.Event, log_cb: Any) -> int:
        cmd = WifiteCore._prefix() + args
        log_cb("Motor: " + WifiteCore.engine_name(), "INFO")
        log_cb("Comando: " + " ".join(args), "INFO")
        proc: Optional[subprocess.Popen[bytes]] = None
        reader_done = threading.Event()
        output_queue: queue.Queue[bytes] = queue.Queue()
        stop_started: Optional[float] = None
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                **hidden_process_kwargs(),
            )

            def reader() -> None:
                try:
                    if proc and proc.stdout:
                        for raw in iter(proc.stdout.readline, b""):
                            output_queue.put(raw)
                finally:
                    reader_done.set()

            threading.Thread(target=reader, daemon=True).start()
            while proc.poll() is None or not reader_done.is_set() or not output_queue.empty():
                if stop_event.is_set() and proc.poll() is None:
                    if stop_started is None:
                        stop_started = time.monotonic()
                        proc.terminate()
                        if os.name == "nt":
                            try:
                                run_console([
                                    "wsl.exe", "-d", "kali-linux", "-u", "root", "--",
                                    "pkill", "-INT", "-f", "wifite",
                                ], timeout=8)
                            except Exception:
                                pass
                    elif time.monotonic() - stop_started > 5:
                        proc.kill()
                try:
                    raw = output_queue.get(timeout=0.25)
                except queue.Empty:
                    continue
                line = strip_ansi(decode_console_bytes(raw)).replace("\r", "").strip()
                if line:
                    log_cb(line, "INFO")
            code = proc.wait(timeout=8)
            if stop_event.is_set():
                log_cb("Wifite detenido; restauración de modo administrado solicitada.", "WARNING")
            else:
                log_cb(f"Wifite finalizó con código {code}.", "OK" if code == 0 else "ERROR")
            return code
        except Exception as exc:
            log_cb(str(exc), "ERROR")
            if proc and proc.poll() is None:
                proc.kill()
            return -1

    @staticmethod
    def cracked(log_cb: Any) -> bool:
        try:
            result = run_console(WifiteCore._prefix() + ["wifite", "--cracked"], timeout=30)
            output = strip_ansi(result.stdout + "\n" + result.stderr).strip()
            for line in output.splitlines():
                log_cb(line, "INFO")
            return result.returncode == 0
        except Exception as exc:
            log_cb(str(exc), "ERROR")
            return False


class QualityCore:
    @staticmethod
    def ping(host: str = "8.8.8.8", count: int = 8) -> Dict[str, float]:
        try:
            result = run_console(["ping", "-n", str(count), host], timeout=30)
            values = [int(v) for v in re.findall(r"(?:time|tiempo)[=<]\s*(\d+)", result.stdout, re.IGNORECASE)]
            loss_match = re.search(r"(\d+)%\s*(?:loss|p[eé]rdida|perdidos)", result.stdout, re.IGNORECASE)
            return {
                "ping": statistics.mean(values) if values else 0.0,
                "jitter": statistics.stdev(values) if len(values) > 1 else 0.0,
                "loss": float(loss_match.group(1)) if loss_match else (0.0 if values else 100.0),
            }
        except Exception:
            return {"ping": 0.0, "jitter": 0.0, "loss": 100.0}

    @staticmethod
    def http_throughput(duration: float = 6.0) -> float:
        if requests is None:
            return 0.0
        url = "https://speedtest.tele2.net/10MB.zip"
        start = time.perf_counter()
        size = 0
        try:
            with requests.get(url, stream=True, timeout=8) as response:
                response.raise_for_status()
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if time.perf_counter() - start >= duration:
                        break
            elapsed = max(0.001, time.perf_counter() - start)
            return size * 8 / elapsed / 1_000_000
        except Exception:
            return 0.0

    @staticmethod
    def speedtest() -> Tuple[float, float]:
        if Speedtest is None:
            return 0.0, 0.0
        test = Speedtest()
        test.get_best_server()
        return test.download() / 1_000_000, test.upload() / 1_000_000


# =========================================================
# === DEPENDENCY MANAGER ===
# =========================================================
class DependencyManager:

    @staticmethod
    def check_tool(name: str) -> Tuple[bool, str]:
        """
        Retorna (encontrado, ruta_o_mensaje).
        Usa shutil.which + rutas Windows tipicas.
        """
        path = find_tool_binary(name)
        if path:
            args = [path, "--version"]
            if name == "aircrack-ng":
                args = [path, "--help"]
            try:
                result = run_console(args, timeout=15)
                combined = (result.stdout + "\n" + result.stderr).strip()
                broken_tokens = (
                    "no se reconoce", "not recognized", "command not found",
                    "cannot find", "no such file", "no se encuentra",
                )
                if any(token in combined.lower() for token in broken_tokens):
                    return False, f"Instalacion incompleta: {path}"
                if result.returncode == 0 or combined:
                    version = next((line.strip() for line in combined.splitlines() if line.strip()), "OK")
                    return True, f"{path} · {version[:100]}"
            except Exception as exc:
                return False, f"No ejecutable: {path} ({exc})"
        return False, "No encontrado en PATH ni rutas estandar"

    @staticmethod
    def check_all() -> Dict[str, Tuple[bool, str]]:
        return {name: DependencyManager.check_tool(name) for name in TOOLS_CONFIG}

    @staticmethod
    def check_choco() -> Tuple[bool, str]:
        path = find_tool_binary("choco")
        if path:
            return True, path
        return False, "No encontrado"

    @staticmethod
    def install_choco() -> Tuple[bool, str]:
        ps_cmd = (
            "Set-ExecutionPolicy Bypass -Scope Process -Force; "
            "[System.Net.ServicePointManager]::SecurityProtocol = "
            "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
            "iex ((New-Object System.Net.WebClient).DownloadString("
            "'https://community.chocolatey.org/install.ps1'))"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=180, check=False,
                **hidden_process_kwargs(),
            )
            return result.returncode == 0, result.stdout[-500:]
        except Exception as exc:
            return False, str(exc)

    @staticmethod
    def install_via_choco(pkg: str) -> Tuple[bool, str]:
        choco_ok, choco_path = DependencyManager.check_choco()
        if not choco_ok:
            return False, "Chocolatey no encontrado. Instalalo primero."
        try:
            result = subprocess.run(
                [choco_path, "install", pkg, "-y", "--no-progress"],
                capture_output=True, text=True, timeout=180, check=False,
                **hidden_process_kwargs(),
            )
            ok = result.returncode == 0
            return ok, (result.stdout or result.stderr)[-500:]
        except Exception as exc:
            return False, str(exc)


# =========================================================
# === ADAPTER MANAGER — Alfa AWUS1900 ===
# =========================================================
@dataclass
class AdapterInfo:
    name: str = "Desconocido"
    description: str = ""
    mac: str = ""
    state: str = "Desconectado"
    ssid: str = ""
    bssid: str = ""
    radio_type: str = ""
    auth: str = ""
    cipher: str = ""
    channel: int = 0
    signal: str = ""
    rx_rate: str = ""
    tx_rate: str = ""
    is_alfa: bool = False
    guid: str = ""
    driver_version: str = ""
    driver_date: str = ""
    alfa_detection_method: str = ""


class AdapterManager:
    _alfa_interface_cache: str = ""
    _alfa_interface_cache_at: float = 0.0
    _adapter_list_cache: List[Dict[str, str]] = []
    _adapter_list_cache_at: float = 0.0

    @staticmethod
    def invalidate_caches() -> None:
        """Discard remembered adapters before an explicit physical validation."""
        AdapterManager._alfa_interface_cache = ""
        AdapterManager._alfa_interface_cache_at = 0.0
        AdapterManager._adapter_list_cache = []
        AdapterManager._adapter_list_cache_at = 0.0

    @staticmethod
    def get_alfa_interface_name(force: bool = False) -> str:
        """Fast Windows lookup used by live radar/wardriving loops."""
        if os.name != "nt":
            info = AdapterManager.get_info()
            return info.name if info.is_alfa else ""
        now = time.monotonic()
        if force:
            AdapterManager._alfa_interface_cache = ""
            AdapterManager._alfa_interface_cache_at = 0.0
        if (
            AdapterManager._alfa_interface_cache
            and now - AdapterManager._alfa_interface_cache_at < 5.0
        ):
            return AdapterManager._alfa_interface_cache
        try:
            raw = run_console(["netsh", "wlan", "show", "interfaces"], timeout=8).stdout
            blocks = re.split(r"(?=^\s*(?:Nombre|Name)\s*:)", raw, flags=re.MULTILINE | re.IGNORECASE)
            for block in blocks:
                name_match = re.search(r"^\s*(?:Nombre|Name)\s*:\s*(.+)$", block, re.MULTILINE | re.IGNORECASE)
                desc_match = re.search(
                    r"^\s*(?:Descripci[oó]n|Description)\s*:\s*(.+)$",
                    block, re.MULTILINE | re.IGNORECASE,
                )
                name = name_match.group(1).strip() if name_match else ""
                description = desc_match.group(1).strip() if desc_match else ""
                combined = f"{name} {description}".lower()
                if name and any(token in combined for token in ALFA_FINGERPRINTS):
                    AdapterManager._alfa_interface_cache = name
                    AdapterManager._alfa_interface_cache_at = now
                    return name
        except Exception:
            pass
        AdapterManager._alfa_interface_cache = ""
        AdapterManager._alfa_interface_cache_at = 0.0
        return ""

    @staticmethod
    def get_info(include_driver: bool = False) -> AdapterInfo:
        info = AdapterInfo()
        if os.name != "nt":
            interfaces = [
                item for item in AlfaWslCore.list_interfaces()
                if re.fullmatch(r"[A-Za-z0-9_.-]+", item)
            ]
            if not interfaces:
                return info
            info.name = interfaces[0]
            info.description = "Interfaz wireless Linux nl80211"
            try:
                info.mac = run_console(
                    ["bash", "-lc", f"cat /sys/class/net/{info.name}/address"], timeout=5
                ).stdout.strip()
                state_line = run_console(
                    ["bash", "-lc", f"ip -brief link show {info.name}"], timeout=5
                ).stdout.strip()
                info.state = "Conectado" if " UP " in f" {state_line} " else "Disponible"
                driver = run_console(
                    ["bash", "-lc", f"ethtool -i {info.name} 2>/dev/null"], timeout=5
                ).stdout
                match = re.search(r"^driver:\s*(.+)$", driver, re.MULTILINE)
                info.driver_version = match.group(1).strip() if match else "N/A"
            except Exception:
                pass
            usb = AlfaWslCore.status().lower()
            info.is_alfa = any(
                token in usb for token in (*AlfaWslCore.HARDWARE_IDS, "8814au", "awus1900")
            )
            info.alfa_detection_method = "lsusb + nl80211" if info.is_alfa else "nl80211"
            return info
        try:
            result = run_console(["netsh", "wlan", "show", "interfaces"], timeout=12)
            raw = result.stdout

            def _ex(pattern: str) -> str:
                m = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
                return m.group(1).strip() if m else ""

            # FIX: usar \s*:\s* en lugar de " : " para manejar padding variable
            info.name       = _ex(r"Nombre\s*:\s*(.*)")
            info.description = _ex(r"Descripci[oó]n\s*:\s*(.*)")
            info.guid       = _ex(r"GUID\s*:\s*(.*)")
            info.mac        = _ex(r"Direcci[oó]n(?:\s+f[ií]sica)?\s*:\s*(.*)")
            info.state      = _ex(r"Estado\s*:\s*(.*)")
            info.ssid       = _ex(r"^[ \t]+SSID\s*:\s*(?!BSSID)(.*)")
            info.bssid      = _ex(r"BSSID\s*:\s*(.*)")
            info.radio_type = _ex(r"Tipo de radio\s*:\s*(.*)")
            info.auth       = _ex(r"Autenticaci[oó]n\s*:\s*(.*)")
            info.cipher     = _ex(r"Cifrado\s*:\s*(.*)")
            ch_raw          = _ex(r"Canal\s*:\s*(.*)")
            info.channel    = int(ch_raw) if ch_raw.strip().isdigit() else 0
            info.signal     = _ex(r"Se[ñn]al\s*:\s*(.*)")
            info.rx_rate    = _ex(r"Velocidad de recepci[oó]n(?:\s*\(Mbps\))?\s*:\s*(.*)")
            info.tx_rate    = _ex(r"Velocidad de transmisi[oó]n(?:\s*\(Mbps\))?\s*:\s*(.*)")

        except Exception:
            pass

        # ── Info de driver via PowerShell ─────────────────
        if include_driver and info.name and info.name != "Desconocido":
            drv = AdapterManager._get_driver_info(info.name)
            info.driver_version = drv.get("version", "N/A")
            info.driver_date    = drv.get("date", "N/A")
            info.description    = info.description or drv.get("description", "")

        # Only classify the active adapter; another disconnected Alfa must not
        # turn an Intel interface into an Alfa false positive.
        info.is_alfa, info.alfa_detection_method = AdapterManager._detect_alfa(
            info.name, info.description
        )

        return info

    @staticmethod
    def _detect_alfa(adapter_name: str, adapter_description: str = "") -> Tuple[bool, str]:
        """
        Intenta detectar Alfa AWUS1900 mediante 4 metodos independientes.
        Retorna (is_alfa, metodo_que_lo_detecto).
        """
        name_lower = (adapter_name + " " + adapter_description).lower()

        # Metodo 1: nombre del adaptador en netsh
        if any(fp in name_lower for fp in ALFA_FINGERPRINTS):
            return True, "netsh name match"
        # Only spend time resolving PnP data for plausible USB Wi-Fi devices.
        # A Realtek PCIe Ethernet controller is not evidence of an Alfa antenna.
        wireless_usb_candidate = (
            "usb" in name_lower
            and any(hint in name_lower for hint in ("wireless", "wi-fi", "wifi", "802.11"))
            and not any(hint in name_lower for hint in ("ethernet", "gbe", "pcie"))
        )
        if not wireless_usb_candidate:
            return False, "No detectada"

        # Metodo 2: Get-NetAdapter for this exact interface only.
        try:
            safe_name = adapter_name.replace("'", "")
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-NetAdapter -Name '{safe_name}' -ErrorAction SilentlyContinue | "
                 "Select-Object Name,InterfaceDescription,MacAddress,PnPDeviceID | ConvertTo-Json"],
                capture_output=True, text=True, timeout=8, check=False,
                **hidden_process_kwargs(),
            )
            out_lower = result.stdout.lower()
            if any(fp in out_lower for fp in ALFA_FINGERPRINTS):
                return True, "Get-NetAdapter"
        except Exception:
            pass

        # Metodo 3: Resolve only the exact interface PnP ID.
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$a=Get-NetAdapter -Name '{safe_name}' -ErrorAction SilentlyContinue;"
                 "if($a){Get-PnpDevice -InstanceId $a.PnPDeviceID -ErrorAction SilentlyContinue | "
                 "Select-Object FriendlyName,HardwareID | ConvertTo-Json}"],
                capture_output=True, text=True, timeout=10, check=False,
                **hidden_process_kwargs(),
            )
            out_lower = result.stdout.lower()
            if any(fp in out_lower for fp in ALFA_FINGERPRINTS):
                return True, "Get-PnpDevice USB"
        except Exception:
            pass

        # Metodo 4: WMI exact connection name.
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WmiObject Win32_NetworkAdapter | "
                 f"Where-Object {{$_.NetConnectionID -eq '{safe_name}'}} | "
                 "Select-Object Name,Description,MACAddress | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10, check=False,
                **hidden_process_kwargs(),
            )
            out_lower = result.stdout.lower()
            if any(fp in out_lower for fp in ALFA_FINGERPRINTS):
                return True, "WMI Win32_NetworkAdapter"
        except Exception:
            pass

        return False, "No detectada"

    @staticmethod
    def _get_driver_info(adapter_name: str) -> Dict[str, str]:
        for cached in AdapterManager._adapter_list_cache:
            if cached.get("name", "").casefold() == adapter_name.casefold():
                version = cached.get("version", "")
                if version and version not in ("N/A", "None"):
                    return {
                        "version": version,
                        "date": cached.get("date", "N/A"),
                        "description": cached.get("desc", ""),
                    }
        try:
            safe_name = adapter_name.replace("'", "")
            cmd = (
                f"$a = Get-NetAdapter -Name '{safe_name}' -ErrorAction SilentlyContinue; "
                "if($a){"
                "$d = Get-PnpDeviceProperty -InstanceId $a.PnPDeviceID "
                "-KeyName DEVPKEY_Device_DriverVersion,DEVPKEY_Device_DriverDate "
                "-ErrorAction SilentlyContinue; "
                "[PSCustomObject]@{"
                "Version=($d | Where-Object {$_.KeyName -like '*Version*'} | "
                "Select-Object -ExpandProperty Data);"
                "Date=($d | Where-Object {$_.KeyName -like '*Date*'} | "
                "Select-Object -ExpandProperty Data);"
                "Desc=$a.InterfaceDescription} | ConvertTo-Json}"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=10, check=False,
                **hidden_process_kwargs(),
            )
            import json
            data = json.loads(result.stdout)
            date_value = data.get("Date", "N/A")
            if isinstance(date_value, dict):
                date_value = date_value.get("DateTime") or date_value.get("value") or "N/A"
            return {
                "version"    : str(data.get("Version", "N/A")),
                "date"       : str(date_value),
                "description": str(data.get("Desc", "")),
            }
        except Exception:
            return {}

    @staticmethod
    def list_all_adapters(force: bool = False) -> List[Dict[str, str]]:
        """Lista todos los adaptadores de red del sistema."""
        adapters: List[Dict[str, str]] = []
        if os.name != "nt":
            try:
                raw = json.loads(run_console(["ip", "-j", "link"], timeout=8).stdout)
                wireless = set(
                    item for item in AlfaWslCore.list_interfaces()
                    if re.fullmatch(r"[A-Za-z0-9_.-]+", item)
                )
                for item in raw:
                    name = str(item.get("ifname", ""))
                    adapters.append({
                        "name": name,
                        "desc": "Wireless nl80211" if name in wireless else "Interfaz Linux",
                        "mac": str(item.get("address", "")),
                        "status": str(item.get("operstate", "")),
                        "speed": "N/A",
                    })
            except Exception:
                pass
            return adapters
        now = time.monotonic()
        if (
            not force
            and AdapterManager._adapter_list_cache
            and now - AdapterManager._adapter_list_cache_at < 5.0
        ):
            return [dict(item) for item in AdapterManager._adapter_list_cache]
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapter | Select-Object Name,InterfaceDescription,"
                 "MacAddress,Status,LinkSpeed | ConvertTo-Json"],
                capture_output=True, text=True, timeout=8, check=False,
                **hidden_process_kwargs(),
            )
            import json
            raw = json.loads(result.stdout)
            items = raw if isinstance(raw, list) else [raw]
            for item in items:
                adapters.append({
                    "name"   : str(item.get("Name", "")),
                    "desc"   : str(item.get("InterfaceDescription", "")),
                    "mac"    : str(item.get("MacAddress", "")),
                    "status" : str(item.get("Status", "")),
                    "speed"  : str(item.get("LinkSpeed", "")),
                    "version": "N/A",
                    "date"   : "N/A",
                })
        except Exception:
            pass
        AdapterManager._adapter_list_cache = [dict(item) for item in adapters]
        AdapterManager._adapter_list_cache_at = now
        return adapters

    @staticmethod
    def get_alfa_info(include_driver: bool = False, force: bool = False) -> AdapterInfo:
        """Return the physical Alfa even when it is not the connected Internet adapter."""
        if os.name != "nt":
            info = AdapterManager.get_info()
            return info if info.is_alfa else AdapterInfo()
        for adapter in AdapterManager.list_all_adapters(force=force):
            is_alfa, method = AdapterManager._detect_alfa(
                adapter.get("name", ""), adapter.get("desc", "")
            )
            if not is_alfa:
                continue
            info = AdapterInfo(
                name=adapter.get("name", "Desconocido"),
                description=adapter.get("desc", ""),
                mac=adapter.get("mac", ""),
                state=adapter.get("status", "Disponible"),
                is_alfa=True,
                alfa_detection_method=method,
            )
            if include_driver:
                driver = AdapterManager._get_driver_info(info.name)
                info.driver_version = driver.get("version", "N/A")
                info.driver_date = driver.get("date", "N/A")
                info.description = info.description or driver.get("description", "")
            return info
        return AdapterInfo()


# =========================================================
# === CREDENCIALES WI-FI GUARDADAS (SOLO MEMORIA) ===
# =========================================================
@dataclass
class SavedWifiProfile:
    name: str
    auth: str = "Desconocida"
    key_kind: str = "No determinada"
    recoverable: bool = False


class WifiCredentialCore:
    """Read credentials already stored by the local operating system."""

    WINDOWS_PROFILE_LABELS = (
        "perfil de todos los usuarios", "all user profile", "perfil de usuario",
    )
    WINDOWS_KEY_LABELS = ("contenido de la clave", "key content")
    WINDOWS_AUTH_LABELS = ("autenticación", "autenticacion", "authentication")
    WINDOWS_SECURITY_KEY_LABELS = ("clave de seguridad", "security key")

    @staticmethod
    def is_windows_admin() -> bool:
        if os.name != "nt":
            return bool(hasattr(os, "geteuid") and os.geteuid() == 0)
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def classify(auth: str, detail: str = "") -> Tuple[str, bool]:
        normalized = (auth or "").casefold()
        security_key = WifiCredentialCore._value_for_labels(
            detail, WifiCredentialCore.WINDOWS_SECURITY_KEY_LABELS
        ).casefold()
        if any(token in normalized for token in ("abierta", "open", "ninguno", "none")):
            return "Red abierta", False
        if any(token in normalized for token in ("enterprise", "802.1x")):
            return "Credenciales 802.1X", False
        if any(token in normalized for token in ("personal", "psk", "sae", "wpa")):
            if any(token in security_key for token in ("ausente", "absent", "no presente")):
                return "PSK no guardada", False
            return "PSK guardada", True
        return "No determinada", False

    @staticmethod
    def _value_for_labels(output: str, labels: Tuple[str, ...]) -> str:
        for line in output.splitlines():
            if ":" not in line:
                continue
            label, value = line.split(":", 1)
            if any(token in label.strip().lower() for token in labels):
                return value.strip()
        return ""

    @staticmethod
    def _parse_windows_profile_names(output: str) -> List[str]:
        profiles: List[str] = []
        for line in output.splitlines():
            if ":" not in line:
                continue
            label, value = line.split(":", 1)
            if any(token in label.strip().lower() for token in WifiCredentialCore.WINDOWS_PROFILE_LABELS):
                name = value.strip()
                if name and name not in profiles:
                    profiles.append(name)
        return profiles

    @staticmethod
    def list_profiles() -> List[SavedWifiProfile]:
        if os.name == "nt":
            listing = run_console(["netsh", "wlan", "show", "profiles"], timeout=15)
            profiles: List[SavedWifiProfile] = []
            for name in WifiCredentialCore._parse_windows_profile_names(listing.stdout):
                detail = run_console(["netsh", "wlan", "show", "profile", f"name={name}"], timeout=12)
                auth = WifiCredentialCore._value_for_labels(
                    detail.stdout, WifiCredentialCore.WINDOWS_AUTH_LABELS
                ) or "Desconocida"
                key_kind, recoverable = WifiCredentialCore.classify(auth, detail.stdout)
                profiles.append(SavedWifiProfile(
                    name=name, auth=auth, key_kind=key_kind, recoverable=recoverable
                ))
            return profiles

        result = run_console(
            ["nmcli", "-t", "--escape", "no", "-f", "NAME,TYPE", "connection", "show"],
            timeout=15,
        )
        profiles = []
        for line in result.stdout.splitlines():
            if not line.endswith(":802-11-wireless"):
                continue
            name = line.rsplit(":", 1)[0]
            security = run_console(
                [
                    "nmcli", "-g", "802-11-wireless-security.key-mgmt",
                    "connection", "show", name,
                ],
                timeout=12,
            ).stdout.strip().casefold()
            if "owe" in security:
                auth, key_kind, recoverable = "OWE", "Sin PSK (OWE)", False
            elif "eap" in security or "8021x" in security:
                auth = "Enterprise/802.1X"
                key_kind, recoverable = WifiCredentialCore.classify(auth)
            elif "sae" in security:
                auth = "WPA3-Personal"
                key_kind, recoverable = "PSK administrada por NetworkManager", True
            elif "psk" in security:
                auth = "WPA/WPA2-Personal"
                key_kind, recoverable = "PSK administrada por NetworkManager", True
            elif not security or security == "none":
                auth = "Abierta"
                key_kind, recoverable = WifiCredentialCore.classify(auth)
            else:
                auth, key_kind, recoverable = security, "No determinada", False
            profiles.append(SavedWifiProfile(
                name=name, auth=auth, key_kind=key_kind, recoverable=recoverable,
            ))
        return profiles

    @staticmethod
    def reveal(profile_name: str) -> Tuple[bool, str]:
        name = clamp_str(profile_name.strip(), 256)
        if not name:
            return False, "Perfil vacío"
        if os.name == "nt":
            if not WifiCredentialCore.is_windows_admin():
                return False, (
                    "Windows requiere permisos de administrador para revelar claves PSK guardadas."
                )
            result = run_console(
                ["netsh", "wlan", "show", "profile", f"name={name}", "key=clear"],
                timeout=15,
            )
            password = WifiCredentialCore._value_for_labels(
                result.stdout, WifiCredentialCore.WINDOWS_KEY_LABELS
            )
            if password:
                return True, password
            combined = (result.stdout + "\n" + result.stderr).lower()
            if "acceso denegado" in combined or "access is denied" in combined:
                return False, "Windows denegó acceso; ejecuta la aplicación como administrador."
            security_key = WifiCredentialCore._value_for_labels(
                result.stdout, WifiCredentialCore.WINDOWS_SECURITY_KEY_LABELS
            ).casefold()
            if any(token in security_key for token in ("presente", "present")):
                return False, (
                    "La PSK existe, pero una directiva de Windows impidió mostrarla en texto claro."
                )
            return False, "El perfil no contiene una clave PSK recuperable."

        result = run_console(
            ["nmcli", "--show-secrets", "-g", "802-11-wireless-security.psk", "connection", "show", name],
            timeout=15,
        )
        password = result.stdout.strip()
        if result.returncode == 0 and password:
            return True, password
        return False, (result.stderr.strip() or "NetworkManager no entregó una clave PSK.")


# =========================================================
# === RECON CORE ===
# =========================================================
@dataclass
class NetworkEntry:
    ssid: str = ""
    bssid: str = ""
    vendor: str = ""
    signal: str = ""
    radio: str = ""
    channel: str = ""
    frequency_mhz: int = 0
    auth: str = ""
    cipher: str = ""
    rates: str = ""
    score: int = 0
    score_label: str = ""
    recommendation: str = ""
    hidden: bool = False


class ReconCore:

    @staticmethod
    def scan(interface: str = "") -> List[NetworkEntry]:
        """Scan with a specific Windows radio instead of whichever adapter is connected."""
        try:
            if os.name != "nt":
                native = AlfaWslCore.scan_networks()
                return native if native else [ReconCore._error_entry("Sin redes detectadas")]
            args = ["netsh", "wlan", "show", "networks"]
            if interface:
                args.append(f"interface={interface}")
            args.append("mode=bssid")
            with WLAN_SCAN_LOCK:
                # WLAN AutoConfig refreshes the cache in the background; one
                # bounded query keeps radar and wardriving responsive.
                result = run_console(args, timeout=15)
            networks = ReconCore._parse(result.stdout)
            return networks if networks else [ReconCore._error_entry("Sin redes detectadas")]
        except Exception as exc:
            return [ReconCore._error_entry(str(exc))]

    @staticmethod
    def _error_entry(msg: str) -> NetworkEntry:
        e = NetworkEntry()
        e.ssid = f"ERROR: {msg[:80]}"
        return e

    @staticmethod
    def _parse(data: str) -> List[NetworkEntry]:
        """
        Parser robusto del output de:
        netsh wlan show networks mode=bssid

        FIX v2.1: El regex de SSID ahora usa \\s*:\\s* para manejar
        el padding variable que usa netsh en Windows.
        """
        networks: List[NetworkEntry] = []
        current_ssid   = ""
        current_auth   = "Desconocido"
        current_cipher = "Desconocido"
        current: Optional[NetworkEntry] = None

        for raw_line in data.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # ── Linea de SSID (ej: "SSID 1                  : MiRed") ──
            # FIX: usar \s*:\s* en lugar de " : " literal
            if re.match(r"^SSID \d+\s*:", line):
                m = re.search(r"^SSID \d+\s*:\s*(.*)", line)
                raw_ssid = m.group(1).strip() if m else ""
                current_ssid   = raw_ssid if raw_ssid else "<SSID Oculto>"
                current_auth   = "Desconocido"
                current_cipher = "Desconocido"

            # ── Autenticacion ──
            elif re.match(r"^Autenticaci", line, re.IGNORECASE):
                current_auth = line.split(":", 1)[1].strip()

            # ── Cifrado ──
            elif re.match(r"^Cifrado", line, re.IGNORECASE):
                current_cipher = line.split(":", 1)[1].strip()

            # ── BSSID (inicia nuevo entry) ──
            elif re.match(r"^BSSID \d+\s*:", line):
                if current is not None:
                    networks.append(current)
                bssid_val = re.sub(r"^BSSID\s+\d+\s*:\s*", "", line).strip()
                sc, lbl, rec = security_score(current_auth, current_cipher)
                current = NetworkEntry(
                    ssid=current_ssid,
                    bssid=bssid_val,
                    vendor=get_vendor(bssid_val),
                    auth=current_auth,
                    cipher=current_cipher,
                    score=sc,
                    score_label=lbl,
                    recommendation=rec,
                    hidden=(current_ssid == "<SSID Oculto>"),
                )

            # ── Campos del BSSID actual ──
            elif current is not None:
                # Señal (ej: "Señal : 54%")
                if re.match(r"^Se[ñn]al\s*:", line, re.IGNORECASE):
                    current.signal = signal_to_dbm(line.split(":", 1)[1].strip())

                # Tipo de radio
                elif re.match(r"^Tipo de radio\s*:", line, re.IGNORECASE):
                    current.radio = line.split(":", 1)[1].strip()

                # Canal
                elif re.match(r"^Canal\s*:", line, re.IGNORECASE):
                    current.channel = line.split(":", 1)[1].strip()

                # Velocidades basicas
                elif re.match(r"^Velocidades b[áa]", line, re.IGNORECASE):
                    current.rates += line.split(":", 1)[1].strip() + " "

        # Agregar ultimo entry
        if current is not None:
            networks.append(current)

        return networks

    @staticmethod
    def get_local_ip() -> str:
        try:
            result = run_console(["ipconfig"], timeout=10)
            blocks = re.split(r"\n\n", result.stdout)
            for block in blocks:
                if any(kw in block.lower() for kw in ("wi-fi", "inal", "wireless")):
                    m = re.search(r"IPv4[^:]*:\s*([\d.]+)", block)
                    if m:
                        return m.group(1)
        except Exception:
            pass
        return "N/A"


# =========================================================
# === CAPTURE CORE ===
# =========================================================
class CaptureCore:

    @staticmethod
    def list_interfaces() -> List[str]:
        tshark_bin = find_tool_binary("tshark")
        if not tshark_bin:
            return ["ERROR: tshark no instalado — instalar Wireshark primero"]
        try:
            result = subprocess.run(
                [tshark_bin, "-D"],
                capture_output=True, text=True, timeout=TOOL_TIMEOUT, check=False,
                **hidden_process_kwargs(),
            )
            ifaces: List[str] = []
            for line in result.stdout.splitlines():
                m = re.match(r"(\d+)\. (.*)", line.strip())
                if m:
                    ifaces.append(f"{m.group(1)}: {m.group(2)}")
            return ifaces if ifaces else ["Sin interfaces disponibles (verificar Npcap)"]
        except Exception as exc:
            return [f"Error: {exc}"]

    @staticmethod
    def capture(
        iface_index: str,
        output_file: Path,
        bssid_filter: str,
        timeout_sec: int,
        stop_event: threading.Event,
        log_cb: Any,
    ) -> bool:
        tshark_bin = find_tool_binary("tshark")
        if not tshark_bin:
            log_cb("[CAPTURE] tshark no encontrado. Instalar Wireshark.", "ERROR")
            return False
        CAPTURE_DIR.mkdir(exist_ok=True)
        bssid_clean = re.sub(r"[^0-9a-fA-F:]", "", bssid_filter)[:17]
        cmd: List[str] = [
            tshark_bin, "-i", iface_index,
            "-w", str(output_file),
            "-a", f"duration:{timeout_sec}",
        ]
        log_cb(f"[CAPTURE] {' '.join(cmd)}", "INFO")
        try:
            with tempfile.TemporaryFile() as error_stream:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=error_stream,
                    **hidden_process_kwargs(),
                )
                while proc.poll() is None:
                    if stop_event.is_set():
                        proc.terminate()
                        try:
                            proc.wait(timeout=4)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                        log_cb("[CAPTURE] Detenido.", "WARNING")
                        return False
                    time.sleep(0.35)
                error_stream.seek(0)
                diagnostics = decode_console_bytes(error_stream.read()).strip()
            valid = proc.returncode == 0 and output_file.exists() and output_file.stat().st_size > 32
            if not valid:
                log_cb("[CAPTURE] Fallo TShark: " + (diagnostics[-700:] or "sin paquetes"), "ERROR")
                return False

            check = run_console([tshark_bin, "-r", str(output_file), "-c", "1"], timeout=15)
            if check.returncode != 0 or not check.stdout.strip():
                log_cb("[CAPTURE] Archivo creado, pero no contiene paquetes decodificables.", "ERROR")
                return False
            log_cb(f"[CAPTURE] Evidencia completa: {output_file}", "OK")

            # A display filter is valid while reading an existing capture. Keep
            # the full evidence and create a target-only derivative.
            if bssid_clean:
                filtered = output_file.with_name(output_file.stem + "_target" + output_file.suffix)
                post = run_console([
                    tshark_bin, "-r", str(output_file), "-Y", f"wlan.addr=={bssid_clean}",
                    "-w", str(filtered),
                ], timeout=max(20, timeout_sec))
                if post.returncode == 0 and filtered.exists() and filtered.stat().st_size > 32:
                    log_cb(f"[CAPTURE] Derivada filtrada: {filtered}", "OK")
                else:
                    log_cb("[CAPTURE] Sin tramas 802.11 del BSSID; se conserva la evidencia completa.", "WARNING")
            return True
        except Exception as exc:
            log_cb(f"[CAPTURE] Error: {exc}", "ERROR")
            return False


@dataclass
class CaptureSummary:
    path: str
    size: int
    sha256: str
    frames: int = 0
    beacons: int = 0
    probes: int = 0
    deauth: int = 0
    eapol: int = 0
    wps: int = 0
    pmkid: int = 0
    valid: bool = False


class CaptureAnalysisCore:
    @staticmethod
    def _count(tshark: str, path: Path, display_filter: str = "") -> int:
        cmd = [tshark, "-r", str(path)]
        if display_filter:
            cmd += ["-Y", display_filter]
        cmd += ["-T", "fields", "-e", "frame.number"]
        try:
            result = run_console(cmd, timeout=60)
            if result.returncode != 0:
                return 0
            return len([line for line in result.stdout.splitlines() if line.strip()])
        except Exception:
            return 0

    @staticmethod
    def analyze(path: Path) -> CaptureSummary:
        summary = CaptureSummary(
            path=str(path), size=path.stat().st_size if path.exists() else 0,
            sha256=file_sha256(path) if path.exists() else "",
        )
        tshark = find_tool_binary("tshark")
        if not tshark or not path.exists() or summary.size <= 32:
            return summary
        summary.frames = CaptureAnalysisCore._count(tshark, path)
        summary.beacons = CaptureAnalysisCore._count(tshark, path, "wlan.fc.type_subtype == 0x0008")
        summary.probes = CaptureAnalysisCore._count(
            tshark, path, "wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005"
        )
        summary.deauth = CaptureAnalysisCore._count(tshark, path, "wlan.fc.type_subtype == 0x000c")
        summary.eapol = CaptureAnalysisCore._count(tshark, path, "eapol")
        summary.wps = CaptureAnalysisCore._count(tshark, path, "wps")
        summary.pmkid = CaptureAnalysisCore._count(tshark, path, "wlan.rsn.ie.pmkid")
        summary.valid = summary.frames > 0
        return summary

    @staticmethod
    def convert_22000(path: Path, log_cb: Any) -> Optional[Path]:
        output = path.with_suffix(".22000")
        local = find_tool_binary("hcxpcapngtool")
        try:
            if local:
                result = run_console([local, "-o", str(output), str(path)], timeout=120)
            else:
                source_linux = AlfaWslCore._wsl_path(path)
                output_linux = AlfaWslCore._wsl_path(output)
                script = (
                    "if command -v hcxpcapngtool >/dev/null 2>&1; then "
                    f"hcxpcapngtool -o '{output_linux}' '{source_linux}'; "
                    "else echo 'FALTA hcxpcapngtool' >&2; exit 127; fi"
                )
                result = run_console([
                    "wsl.exe", "-d", "kali-linux", "--", "bash", "-lc", script
                ], timeout=120)
            combined = (result.stdout + "\n" + result.stderr).strip()
            for line in combined.splitlines()[-20:]:
                log_cb("[HCX] " + line, "INFO")
            if result.returncode == 0 and output.exists() and output.stat().st_size > 0:
                log_cb(f"[HCX] Hash 22000: {output}", "OK")
                return output
            log_cb("[HCX] No se obtuvo hash 22000 válido.", "WARNING")
        except Exception as exc:
            log_cb(f"[HCX] {exc}", "ERROR")
        return None


# =========================================================
# === CRACK CORE ===
# =========================================================
class CrackCore:

    @staticmethod
    def aircrack(
        cap_file: Path,
        wordlist: Path,
        bssid: str,
        log_cb: Any,
        stop_event: threading.Event,
    ) -> Optional[str]:
        bin_path = find_tool_binary("aircrack-ng")
        if not bin_path:
            log_cb("[AIRCRACK] aircrack-ng no encontrado. Ver tab Herramientas.", "ERROR")
            return None
        bssid_clean = re.sub(r"[^0-9a-fA-F:-]", "", bssid)[:17]
        cmd = [bin_path, "-w", str(wordlist), "-b", bssid_clean, str(cap_file)]
        log_cb(f"[AIRCRACK] {' '.join(cmd)}", "INFO")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                **hidden_process_kwargs(),
            )
            for line in proc.stdout:  # type: ignore[union-attr]
                if stop_event.is_set():
                    proc.terminate()
                    return None
                line = line.strip()
                if line:
                    log_cb(f"  {line}", "INFO")
                m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", line, re.IGNORECASE)
                if m:
                    proc.terminate()
                    return m.group(1)
            proc.wait()
        except Exception as exc:
            log_cb(f"[AIRCRACK] {exc}", "ERROR")
        return None

    @staticmethod
    def hashcat(
        hash_file: Path,
        wordlist: Path,
        mode: int,
        log_cb: Any,
        stop_event: threading.Event,
    ) -> None:
        bin_path = find_tool_binary("hashcat")
        if not bin_path:
            log_cb("[HASHCAT] hashcat no encontrado. Ver tab Herramientas.", "ERROR")
            return
        cmd = [
            bin_path, f"-m{mode}", "-a0",
            str(hash_file), str(wordlist),
            "--status", "--status-timer=5", "--potfile-disable", "--force",
        ]
        log_cb(f"[HASHCAT] {' '.join(cmd)}", "INFO")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                **hidden_process_kwargs(),
            )
            for line in proc.stdout:  # type: ignore[union-attr]
                if stop_event.is_set():
                    proc.terminate()
                    return
                line = line.strip()
                if line:
                    log_cb(f"  {line}", "INFO")
            proc.wait()
        except Exception as exc:
            log_cb(f"[HASHCAT] {exc}", "ERROR")


# =========================================================
# === ATTACK CORE — netsh dictionary ===
# =========================================================
class AttackCore:

    @staticmethod
    def _build_profile(ssid: str, password: str, auth: str) -> str:
        hex_ssid = ssid.encode("utf-8").hex()
        ssid_xml = xml_escape(ssid)
        password_xml = xml_escape(password)
        au = auth.upper()
        auth_tag = "WPA2PSK" if "WPA2" in au else "WPAPSK" if "WPA" in au else "open"
        enc_tag  = "AES"     if ("CCMP" in au or "WPA2" in au) else "TKIP"
        return (
            '<?xml version="1.0"?>\n'
            '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">\n'
            '  <name>' + ssid_xml + '</name>\n'
            '  <SSIDConfig><SSID><hex>' + hex_ssid + '</hex>'
            '<name>' + ssid_xml + '</name></SSID></SSIDConfig>\n'
            '  <connectionType>ESS</connectionType>\n'
            '  <connectionMode>manual</connectionMode>\n'
            '  <MSM><security><authEncryption>\n'
            '    <authentication>' + auth_tag + '</authentication>\n'
            '    <encryption>' + enc_tag + '</encryption>\n'
            '    <useOneX>false</useOneX>\n'
            '  </authEncryption>\n'
            '  <sharedKey><keyType>passPhrase</keyType>'
            '<protected>false</protected>'
            '<keyMaterial>' + password_xml + '</keyMaterial>'
            '</sharedKey></security></MSM>\n'
            '</WLANProfile>'
        )

    @staticmethod
    def test_credential(ssid: str, password: str, auth: str) -> bool:
        xml = AttackCore._build_profile(ssid, password, auth)
        previous_ssid = AdapterManager.get_info().ssid
        with tempfile.TemporaryDirectory(prefix="wireless_audit_profile_") as temp_dir:
            work = Path(temp_dir)
            profile_path = work / "candidate.xml"
            profile_path.write_text(xml, encoding="utf-8")
            # Preserve an existing user profile in its DPAPI-protected export.
            run_console([
                "netsh", "wlan", "export", "profile", f"name={ssid}", f"folder={work}"
            ], timeout=12)
            backups = [p for p in work.glob("*.xml") if p.name != profile_path.name]
            try:
                added = run_console([
                    "netsh", "wlan", "add", "profile", f"filename={profile_path}", "user=current"
                ], timeout=12)
                if added.returncode != 0:
                    return False
                run_console(["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"], timeout=12)
                time.sleep(CONNECT_SLEEP)
                check = run_console(["netsh", "wlan", "show", "interfaces"], timeout=12)
                connected = bool(re.search(r"Estado\s*:\s*(conectado|connected)", check.stdout, re.IGNORECASE))
                current = re.search(r"^[ \t]+SSID\s*:\s*(?!BSSID)(.*)$", check.stdout, re.IGNORECASE | re.MULTILINE)
                return connected and bool(current and current.group(1).strip() == ssid)
            finally:
                run_console(["netsh", "wlan", "delete", "profile", f"name={ssid}"], timeout=12)
                for backup in backups:
                    run_console([
                        "netsh", "wlan", "add", "profile", f"filename={backup}", "user=current"
                    ], timeout=12)
                if previous_ssid:
                    run_console([
                        "netsh", "wlan", "connect", f"name={previous_ssid}", f"ssid={previous_ssid}"
                    ], timeout=12)


# =========================================================
# === NMAP CORE ===
# =========================================================
class NmapCore:

    @staticmethod
    def host_discovery(
        target: str,
        log_cb: Any,
        stop_event: threading.Event,
    ) -> List[Dict[str, str]]:
        bin_path = find_tool_binary("nmap")
        if not bin_path:
            log_cb("[NMAP] nmap no encontrado. Ver tab Herramientas.", "ERROR")
            return []
        target_clean = clamp_str(re.sub(r"[^0-9./]", "", target), MAX_IP_LENGTH)
        cmd = [bin_path, "-sn", "--open", target_clean]
        log_cb(f"[NMAP] {' '.join(cmd)}", "INFO")
        hosts: List[Dict[str, str]] = []
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                **hidden_process_kwargs(),
            )
            current_ip = ""
            current_host = ""
            for line in proc.stdout:  # type: ignore[union-attr]
                if stop_event.is_set():
                    proc.terminate()
                    return hosts
                line = line.strip()
                if line:
                    log_cb(f"  {line}", "INFO")
                mi = re.search(r"Nmap scan report for (.+)", line)
                if mi:
                    text = mi.group(1)
                    ip_m = re.search(r"\(?([\d.]+)\)?$", text)
                    current_ip   = ip_m.group(1) if ip_m else text
                    current_host = re.sub(r"\s*\([\d.]+\)\s*", "", text).strip()
                if "Host is up" in line and current_ip:
                    hosts.append({"ip": current_ip, "hostname": current_host})
            proc.wait()
        except Exception as exc:
            log_cb(f"[NMAP] {exc}", "ERROR")
        return hosts

    @staticmethod
    def service_scan(
        ip: str,
        log_cb: Any,
        stop_event: threading.Event,
    ) -> None:
        bin_path = find_tool_binary("nmap")
        if not bin_path:
            log_cb("[NMAP] nmap no encontrado.", "ERROR")
            return
        ip_clean = clamp_str(re.sub(r"[^0-9.]", "", ip), MAX_IP_LENGTH)
        cmd = [bin_path, "-sV", "-sC", "-O", "--open", ip_clean]
        log_cb(f"[NMAP-SVC] {' '.join(cmd)}", "INFO")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                **hidden_process_kwargs(),
            )
            for line in proc.stdout:  # type: ignore[union-attr]
                if stop_event.is_set():
                    proc.terminate()
                    return
                l = line.strip()
                if l:
                    log_cb(f"  {l}", "INFO")
            proc.wait()
        except Exception as exc:
            log_cb(f"[NMAP] {exc}", "ERROR")


# =========================================================
# === REPORT GENERATOR ===
# =========================================================
class ReportGenerator:

    @staticmethod
    def generate(
        networks: List[NetworkEntry],
        adapter: AdapterInfo,
        prefix: str,
        quality: Optional[Dict[str, float]] = None,
        capabilities: Optional[CapabilitySnapshot] = None,
    ) -> Path:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        clean = clamp_str(re.sub(r"[^a-zA-Z0-9_\-]", "_", prefix), MAX_PREFIX_LENGTH)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = REPORTS_DIR / (clean + "_" + ts + ".html")
        valid = [n for n in networks if n.bssid]
        critical = len([n for n in valid if n.score < 40])
        review = len([n for n in valid if 40 <= n.score < 70])
        robust = len([n for n in valid if n.score >= 70])
        run_id = hashlib.sha256(f"{ts}|{adapter.mac}|{len(valid)}".encode()).hexdigest()[:16].upper()

        rows_parts: List[str] = []
        for n in valid:
            color = "#3fb950" if n.score >= 70 else "#d29922" if n.score >= 40 else "#f85149"
            rows_parts.append(
                "<tr>"
                "<td>" + ("🔒 " if n.hidden else "") + safe_html(n.ssid) + "</td>"
                "<td style='font-family:monospace'>" + safe_html(n.bssid) + "</td>"
                "<td>" + safe_html(n.vendor) + "</td>"
                "<td>" + safe_html(n.signal) + "</td>"
                "<td>" + safe_html(n.radio) + "</td>"
                "<td>" + safe_html(n.channel) + "</td>"
                "<td>" + safe_html(n.auth) + "</td>"
                "<td>" + safe_html(n.cipher) + "</td>"
                "<td>" + safe_html(n.rates) + "</td>"
                "<td style='color:" + color + ";font-weight:bold'>"
                + safe_html(n.score_label) + " (" + str(n.score) + "/100)</td>"
                "<td style='font-size:.85em;color:#8b949e'>"
                + safe_html(n.recommendation) + "</td>"
                "</tr>\n"
            )
        rows = "".join(rows_parts)

        channels: Dict[str, int] = defaultdict(int)
        for network in valid:
            channels[network.channel or "?"] += 1
        max_channel = max(channels.values(), default=1)
        channel_rows = "".join(
            "<tr><td>" + safe_html(channel) + "</td><td>" + str(count) + "</td>"
            "<td><div class='bar' style='width:" + str(round(count / max_channel * 100)) + "%'></div></td></tr>"
            for channel, count in sorted(channels.items(), key=lambda item: (not item[0].isdigit(), int(item[0]) if item[0].isdigit() else 999))
        )

        evidence_rows = ""
        if CAPTURE_DIR.exists():
            evidence_parts = []
            captures = sorted(
                [p for p in CAPTURE_DIR.iterdir() if p.is_file()], key=lambda p: p.stat().st_mtime, reverse=True
            )[:20]
            for capture in captures:
                digest = file_sha256(capture)
                evidence_parts.append(
                    "<tr><td>" + safe_html(capture.name) + "</td><td>" + str(capture.stat().st_size) +
                    " bytes</td><td class='mono'>" + digest + "</td></tr>"
                )
            evidence_rows = "".join(evidence_parts)

        quality_html = "<p class='muted'>No se ejecutó una prueba de calidad en esta sesión.</p>"
        if quality:
            quality_html = "<div class='cards'>" + "".join(
                f"<div class='card'><span>{safe_html(key.upper())}</span><b>{value:.1f}</b></div>"
                for key, value in quality.items()
            ) + "</div>"

        capability_html = "<p class='muted'>Diagnóstico de capacidades no adjunto.</p>"
        if capabilities:
            capability_html = (
                "<div class='meta'>"
                f"<div><span>Monitor anunciado</span><b>{'Sí' if capabilities.monitor_advertised else 'No'}</b></div>"
                f"<div><span>Npcap 802.11 raw</span><b>{'Operativo' if capabilities.npcap_dot11 else 'No expuesto'}</b></div>"
                f"<div><span>Alfa AWUS1900</span><b>{'Conectada' if capabilities.alfa_present else 'Registrada / desconectada' if capabilities.alfa_registered else 'No detectada'}</b></div>"
                f"<div><span>Kali WSL2</span><b>{safe_html(capabilities.kali_state)}</b></div>"
                "</div>"
            )

        ts_h = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        page = f"""<!doctype html><html lang='es'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<meta http-equiv='Content-Security-Policy' content="default-src 'self';style-src 'unsafe-inline'">
<title>Wireless Audit Pro · {safe_html(clean)}</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#07100b;color:#d7e7db;font:14px 'Segoe UI',sans-serif}}
header,main{{max-width:1500px;margin:auto;padding:24px}}header{{background:#091a11;border-bottom:1px solid #245b34}}
h1{{margin:0;color:#54ff72;letter-spacing:.04em}}h2{{color:#41e5ff;margin-top:34px}}.muted,span{{color:#82988a}}
.meta,.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.meta div,.card{{background:#0d1c13;border:1px solid #23432d;border-radius:8px;padding:14px}}
.meta b,.card b{{display:block;color:#effff2;margin-top:5px}}.card b{{font-size:22px}}table{{width:100%;border-collapse:collapse;font-size:12px;background:#09150e}}
th,td{{border:1px solid #223a2a;padding:8px;text-align:left}}th{{color:#66e6ff;background:#102219;position:sticky;top:0}}
.bar{{height:10px;background:#54ff72;border-radius:8px;min-width:3px}}.mono{{font-family:Consolas,monospace;font-size:10px;word-break:break-all}}
.summary{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:18px 0}}.summary div{{padding:18px;border-radius:8px;background:#0d1c13;text-align:center}}
.summary b{{display:block;font-size:30px}}footer{{padding:28px 0;color:#65776a}}@media(max-width:800px){{.meta,.cards{{grid-template-columns:1fr 1fr}}table{{display:block;overflow:auto}}}}
</style></head><body><header><h1>WIRELESS AUDIT PRO</h1><p>Reporte técnico 802.11 · {ts_h} · RUN {run_id}</p></header><main>
<div class='meta'><div><span>Adaptador</span><b>{safe_html(adapter.name)}</b></div><div><span>Descripción</span><b>{safe_html(adapter.description or 'N/A')}</b></div>
<div><span>MAC</span><b class='mono'>{safe_html(adapter.mac or 'N/A')}</b></div><div><span>Driver</span><b>{safe_html(adapter.driver_version or 'N/A')}</b></div></div>
<div class='summary'><div><span>Configuración crítica</span><b style='color:#ff5964'>{critical}</b></div><div><span>Revisión requerida</span><b style='color:#ffb84d'>{review}</b></div><div><span>Configuración robusta</span><b style='color:#54ff72'>{robust}</b></div></div>
<h2>Capacidades del motor</h2>{capability_html}<h2>Inventario 802.11</h2>
<table><tr><th>SSID</th><th>BSSID</th><th>Vendor</th><th>Señal</th><th>Radio</th><th>Canal</th><th>Auth</th><th>Cifrado</th><th>Rates</th><th>Score</th><th>Recomendación</th></tr>{rows}</table>
<h2>Ocupación por canal</h2><table><tr><th>Canal</th><th>AP</th><th>Ocupación relativa</th></tr>{channel_rows}</table>
<h2>Calidad de conexión</h2>{quality_html}<h2>Evidencias de captura</h2>
<table><tr><th>Archivo</th><th>Tamaño</th><th>SHA-256</th></tr>{evidence_rows or '<tr><td colspan="3">Sin capturas asociadas.</td></tr>'}</table>
<footer>Wireless Audit Pro v{VERSION} · Evidencia local · Roger F5</footer></main></body></html>"""

        out.write_text(page, encoding="utf-8")
        return out


# =========================================================
# === GUI ===
# =========================================================
class AuditorGUI(ctk.CTk):

    def __init__(self) -> None:
        super().__init__()
        self._headless_smoke = "--gui-smoke" in sys.argv
        if self._headless_smoke:
            self.withdraw()
        self.title(f"Wireless Audit Pro v{VERSION} — Radar · Wardriving · Alfa AWUS1900")
        self.geometry("1500x920")
        self.minsize(1180, 760)
        self.configure(fg_color=APP_BG)

        self._main_thread_id = threading.get_ident()
        self._ui_tasks: queue.Queue[Any] = queue.Queue()

        self.scan_results: List[NetworkEntry] = []
        self.adapter_info: AdapterInfo = AdapterInfo()
        self._brute_running   = False
        self._brute_auth      = ""
        self._brute_wordlist: Optional[Path] = None
        self._crack_cap:      Optional[Path] = None
        self._crack_wordlist: Optional[Path] = None
        self._cap_out_file:   Optional[Path] = None
        self.last_capture_summary: Optional[CaptureSummary] = None
        self.capabilities = CapabilitySnapshot()
        self.last_report: Optional[Path] = None
        self._credential_passwords: Dict[str, str] = {}
        self._credential_profiles: Dict[str, SavedWifiProfile] = {}
        self._credential_visible_profile = ""
        self._wifite_wordlist: Optional[Path] = None

        self._radar_stop = threading.Event()
        self._radar_seen: set[str] = set()
        self._radar_started_at = 0.0
        self._wardrive_stop = threading.Event()
        self._wardrive_session_id: Optional[int] = None
        self._last_wardrive_session_id: Optional[int] = None
        self._wardrive_markers: Dict[str, Any] = {}
        self._wardrive_best_signal: Dict[str, int] = {}
        self._wardrive_track: List[Tuple[float, float]] = []
        self._wardrive_map_track: List[Tuple[float, float]] = []
        self._wardrive_path: Any = None
        self._wardrive_distance_km = 0.0
        self._wardrive_started_at = 0.0
        self._wardrive_seen: set[str] = set()
        self._wardrive_last_fix_at = 0.0
        self._map_cache_lock = threading.Lock()

        self._stop: Dict[str, threading.Event] = {
            k: threading.Event() for k in ("capture", "crack", "nmap", "wifite")
        }

        for directory in (CAPTURE_DIR, REPORTS_DIR, DATA_DIR, EXPORTS_DIR):
            directory.mkdir(parents=True, exist_ok=True)

        self.wardrive_store = WardriveStore()

        self._style_tree()
        self._build_ui()
        if self._headless_smoke:
            self.withdraw()
        else:
            try:
                self.state("zoomed")
            except Exception:
                pass
        self.gps_manager = GPSManager(self._log)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(80, self._drain_ui_tasks)
        if not self._headless_smoke:
            threading.Thread(target=self._detect_adapter, daemon=True).start()

    def _style_tree(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview",
                    background="#0d1117", foreground="#c9d1d9",
                    fieldbackground="#0d1117", rowheight=26,
                    font=("Courier New", 10))
        s.configure("Treeview.Heading",
                    background="#161b22", foreground="#58a6ff",
                    font=("Segoe UI", 10, "bold"))
        s.map("Treeview", background=[("selected", "#1f6feb")])

    @staticmethod
    def _set_run_buttons(
        start_button: Any, stop_button: Any, running: bool,
        start_color: str = BUTTON_START, stop_color: str = BUTTON_STOP,
    ) -> None:
        """Make the active/pressed action visually unambiguous."""
        start_button.configure(
            state="disabled" if running else "normal",
            fg_color=BUTTON_IDLE if running else start_color,
        )
        stop_button.configure(
            state="normal" if running else "disabled",
            fg_color=stop_color if running else BUTTON_IDLE,
        )

    def _request_stop(self, key: str, stop_button: Any, status: Optional[Any] = None) -> None:
        self._stop[key].set()
        stop_button.configure(state="disabled", fg_color=BUTTON_IDLE)
        if status is not None:
            status.configure(text="DETENIENDO…", text_color=WARNING)

    # ── UI principal ─────────────────────────────────────────
    def _build_ui(self) -> None:
        banner = ctk.CTkFrame(self, height=50, fg_color="#0d1117")
        banner.pack(fill="x")
        ctk.CTkLabel(banner, text=f"  WIRELESS AUDIT PRO  v{VERSION}",
                      font=("Segoe UI", 16, "bold"),
                     text_color=RADAR_GREEN).pack(side="left", padx=16, pady=8)
        self.lbl_banner_alfa = ctk.CTkLabel(
            banner, text="Detectando adaptador...",
            font=("Segoe UI", 11), text_color="#8b949e")
        self.lbl_banner_alfa.pack(side="right", padx=20)

        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(expand=True, fill="both", padx=10, pady=4)
        for t in ["Inicio", "Radar", "Mapa y Wardriving", "Espectro", "Reconocimiento",
                  "Auditoría wireless", "Alfa", "Claves Wi-Fi"]:
            self.tabs.add(t)

        self._build_tab_home()
        self._build_tab_radar()
        self._build_tab_wardrive()
        self._build_tab_spectrum()
        self._build_tab_recon()
        self._build_tab_audit()
        self._build_tab_adapter()
        self._build_tab_credentials()

        btm = ctk.CTkFrame(self, height=110)
        btm.pack(fill="x", padx=10, pady=(0, 8))
        lf = ctk.CTkFrame(btm, width=260, fg_color="transparent")
        lf.pack(side="left", fill="y", padx=(8, 4), pady=6)
        self.prefix_entry = ctk.CTkEntry(lf, placeholder_text="Prefijo reporte", width=210)
        self.prefix_entry.pack(pady=(8, 4))
        ctk.CTkButton(lf, text="Exportar Reporte HTML",
                      command=self._export_report,
                      fg_color="#217346", hover_color="#1e6b40",
                      width=210).pack(pady=4)
        self.console = ctk.CTkTextbox(btm, font=("Courier New", 11), wrap="word")
        self.console.pack(side="right", expand=True, fill="both", padx=(4, 8), pady=6)
        self._log("Framework v" + VERSION + " iniciado.")

    # ── TAB: Inicio / one-click workflow ────────────────────
    def _build_tab_home(self) -> None:
        tab = self.tabs.tab("Inicio")
        hero = ctk.CTkFrame(tab, fg_color="#07140d", border_width=1, border_color="#256f37")
        hero.pack(fill="x", padx=18, pady=(14, 8))
        ctk.CTkLabel(
            hero, text="RADAR · WARDRIVING · 802.11 · EVIDENCIA",
            font=("Segoe UI", 24, "bold"), text_color=RADAR_GREEN,
        ).pack(anchor="w", padx=22, pady=(18, 2))
        ctk.CTkLabel(
            hero,
            text="Radar, mapa, espectro y auditoría con Alfa AWUS1900 o la radio integrada.",
            font=("Segoe UI", 12), text_color="#a9cbb2",
        ).pack(anchor="w", padx=22, pady=(0, 16))

        actions = ctk.CTkFrame(tab, fg_color="transparent")
        actions.pack(fill="x", padx=18, pady=8)
        ctk.CTkButton(
            actions, text="▶ AUDITORÍA COMPLETA", width=230, height=42,
            command=self._start_full_audit, fg_color="#238636", hover_color="#2ea043",
            font=("Segoe UI", 12, "bold"),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            actions, text="Probar capacidades", width=170, height=42,
            command=lambda: threading.Thread(target=self._refresh_capabilities, daemon=True).start(),
            fg_color="#155f75",
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            actions, text="Abrir reportes", width=150, height=42,
            command=lambda: open_local_path(REPORTS_DIR), fg_color="#4b5563",
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            actions, text="Abrir exportaciones", width=170, height=42,
            command=lambda: open_local_path(EXPORTS_DIR), fg_color="#4b5563",
        ).pack(side="left", padx=8)

        body = ctk.CTkFrame(tab, fg_color="transparent")
        body.pack(expand=True, fill="both", padx=18, pady=8)
        body.grid_columnconfigure(0, weight=2)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)
        status_card = ctk.CTkFrame(body, fg_color=PANEL_BG, border_width=1, border_color="#203b2b")
        status_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ctk.CTkLabel(status_card, text="CAPACIDADES DETECTADAS", text_color=CYAN,
                     font=("Consolas", 13, "bold")).pack(anchor="w", padx=18, pady=(16, 6))
        self.home_status = ctk.CTkTextbox(status_card, font=("Consolas", 12), fg_color="#06100a")
        self.home_status.pack(expand=True, fill="both", padx=14, pady=(0, 14))
        self.home_status.insert("end", "Detectando adaptadores y motores…")

        flow_card = ctk.CTkFrame(body, fg_color=PANEL_BG, border_width=1, border_color="#203b2b")
        flow_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        ctk.CTkLabel(flow_card, text="FLUJO INTEGRADO", text_color=RADAR_GREEN,
                     font=("Consolas", 13, "bold")).pack(anchor="w", padx=18, pady=(16, 8))
        workflow = (
            "01  Alfa preferida automáticamente\n\n"
            "02  Radar + espectro 2.4/5 GHz\n\n"
            "03  Mapa y ruta con permiso GPS\n\n"
            "04  Reconocimiento y seguridad\n\n"
            "05  Claves guardadas localmente\n\n"
            "WARD  WiGLE · KML · GeoJSON"
        )
        ctk.CTkLabel(flow_card, text=workflow, justify="left", text_color="#b5d8bd",
                     font=("Consolas", 12)).pack(anchor="w", padx=18, pady=8)

    def _refresh_capabilities(
        self, known_info: Optional[AdapterInfo] = None, force: bool = False,
    ) -> CapabilitySnapshot:
        info = known_info or AdapterManager.get_info()
        capabilities = CapabilityEngine.probe(info.name, force=force)
        self.adapter_info = info
        self.capabilities = capabilities
        lines = [
            f"Radio de Internet  : {info.name}",
            f"Descripción         : {info.description or 'N/A'}",
            f"Estado / SSID       : {info.state} / {info.ssid or 'N/A'}",
            f"Señal / Canal       : {signal_to_dbm(info.signal) if info.signal else 'N/A'} / {info.channel or 'N/A'}",
            "",
            f"Radio de auditoría : {capabilities.alfa_windows_interface or capabilities.alfa_linux_interface or 'Wi-Fi integrada'}",
            f"Alfa en Windows    : {capabilities.alfa_windows_description or 'NO DISPONIBLE'}",
            f"MAC Alfa           : {capabilities.alfa_windows_mac or 'N/A'}",
            f"Driver Alfa        : {capabilities.alfa_windows_driver or 'N/A'}",
            f"Escaneo Alfa nativo: {'OPERATIVO' if capabilities.alfa_native_scan else 'PENDIENTE'}",
            "",
            f"Monitor anunciado   : {'SÍ' if capabilities.monitor_advertised else 'NO'}",
            f"Npcap 802.11 raw    : {'OPERATIVO' if capabilities.npcap_dot11 else 'NO EXPUESTO'}",
            f"Linktypes captura   : {capabilities.capture_linktypes}",
            "",
            f"Alfa AWUS1900       : {'CONECTADA' if capabilities.alfa_present else 'REGISTRADA / DESCONECTADA' if capabilities.alfa_registered else 'NO DETECTADA'}",
            f"Estado USB Alfa     : {capabilities.alfa_usb_state}",
            f"Módulo Kali 8814au  : {'LISTO' if capabilities.alfa_module_ready else 'PENDIENTE'}",
            f"Interfaz RF Kali    : {capabilities.alfa_linux_interface or 'SIN INTERFAZ nl80211'}",
            f"Kali WSL2           : {capabilities.kali_state}",
        ]
        if capabilities.notes:
            lines.extend(["", "Observaciones:"] + ["  · " + note for note in capabilities.notes])

        def update() -> None:
            self.home_status.delete("1.0", "end")
            self.home_status.insert("end", "\n".join(lines))
            if capabilities.alfa_linux_interface:
                banner_text = f"  ALFA RF LISTA · {capabilities.alfa_linux_interface}"
                banner_color = RADAR_GREEN
            elif capabilities.alfa_windows_interface:
                banner_text = f"  ALFA WINDOWS LISTA · {capabilities.alfa_windows_interface}"
                banner_color = RADAR_GREEN
            elif capabilities.alfa_present:
                banner_text = "  ALFA USB DETECTADA · PREPARACIÓN PENDIENTE"
                banner_color = WARNING
            else:
                banner_text = "  INTEL ACTIVA · ALFA DESCONECTADA"
                banner_color = WARNING
            self.lbl_banner_alfa.configure(text=banner_text, text_color=banner_color)
        self._ui_call(update)
        self._log("Capacidades actualizadas.", "OK")
        return capabilities

    def _start_full_audit(self) -> None:
        self._log("Iniciando auditoría completa integrada…", "INFO")
        source = self.scan_source_combo.get()
        threading.Thread(target=self._full_audit_worker, args=(source,), daemon=True).start()

    @staticmethod
    def _scan_with_source(source: str) -> Tuple[List[NetworkEntry], str]:
        if os.name != "nt":
            alfa_results = AlfaWslCore.scan_networks()
            if any(item.bssid for item in alfa_results):
                return alfa_results, "ALFA · LINUX nl80211"
            return [ReconCore._error_entry("Sin interfaz wireless nl80211")], "LINUX · RADIO NO DISPONIBLE"

        if source.startswith("Automático") or source.startswith("Alfa Windows"):
            alfa_interface = AdapterManager.get_alfa_interface_name()
            if alfa_interface:
                alfa_results = ReconCore.scan(alfa_interface)
                if any(item.bssid for item in alfa_results):
                    return alfa_results, f"ALFA · WINDOWS · {alfa_interface}"
            if source.startswith("Alfa Windows"):
                return [ReconCore._error_entry("Alfa no disponible en Windows")], "ALFA WINDOWS NO DISPONIBLE"

        if source.startswith("Alfa Kali") or source.startswith("Kali"):
            AlfaWslCore.ensure_ready(lambda _message, _level: None)
            alfa_results = AlfaWslCore.scan_networks()
            if any(item.bssid for item in alfa_results):
                return alfa_results, "ALFA · KALI nl80211"
            return [ReconCore._error_entry("Alfa sin interfaz o escaneo nl80211 no disponible")], "ALFA KALI NO DISPONIBLE"

        # Automatic mode may use an Alfa already attached to Kali, but it never
        # performs a slow USB/IP transfer behind the user's back.
        if source.startswith("Automático"):
            usb_state = AlfaWslCore.status().lower()
            if "attached" in usb_state or "adjunt" in usb_state:
                kali_interfaces = [
                    item for item in AlfaWslCore.list_interfaces()
                    if re.fullmatch(r"[A-Za-z0-9_.-]+", item)
                ]
                if kali_interfaces:
                    alfa_results = AlfaWslCore.scan_networks()
                    if any(item.bssid for item in alfa_results):
                        return alfa_results, "ALFA · KALI nl80211"

        results = ReconCore.scan()
        return results, "WINDOWS · WI-FI INTEGRADA"

    def _full_audit_worker(self, source: str) -> None:
        try:
            self._refresh_capabilities()
            results, engine = self._scan_with_source(source)
            self.scan_results = results
            self._ui_call(lambda: self._update_radar(results, engine))
            self._ui_call(lambda: self._replace_recon_ui(results))
            report = ReportGenerator.generate(
                results, self.adapter_info, REPORT_DEFAULT_NAME,
                getattr(self, "quality_results", None), self.capabilities,
            )
            self.last_report = report
            self._log(f"Auditoría completa: {report}", "OK")
        except Exception as exc:
            self._log(f"Auditoría completa: {exc}", "ERROR")

    # ── TAB: Dragon Radar ───────────────────────────────────
    def _build_tab_radar(self) -> None:
        tab = self.tabs.tab("Radar")
        controls = ctk.CTkFrame(tab, fg_color=PANEL_BG)
        controls.pack(fill="x", padx=10, pady=(8, 4))
        self.btn_radar_start = ctk.CTkButton(
            controls, text="▶ Activar radar", command=self._start_radar,
            fg_color=BUTTON_START, width=150,
        )
        self.btn_radar_start.pack(side="left", padx=8, pady=8)
        self.btn_radar_stop = ctk.CTkButton(
            controls, text="■ Detener", command=self._stop_radar,
            fg_color=BUTTON_IDLE, state="disabled", width=110,
        )
        self.btn_radar_stop.pack(side="left", padx=4)
        ctk.CTkLabel(controls, text="Intervalo:").pack(side="left", padx=(18, 4))
        self.radar_interval = ctk.CTkEntry(controls, width=55)
        self.radar_interval.insert(0, "4")
        self.radar_interval.pack(side="left")
        ctk.CTkLabel(controls, text="seg", text_color="#8fb59a").pack(side="left", padx=4)
        self.scan_source_combo = ctk.CTkComboBox(
            controls,
            values=[
                "Automático (Alfa preferida)",
                "Alfa Windows (sin WSL)",
                "Wi-Fi integrada Windows",
                "Alfa Kali (monitor)",
            ],
            width=220,
        )
        self.scan_source_combo.set("Automático (Alfa preferida)")
        self.scan_source_combo.pack(side="left", padx=(14, 4))
        self.lbl_radar_status = ctk.CTkLabel(controls, text="RADAR EN ESPERA", text_color=WARNING,
                                             font=("Consolas", 11, "bold"))
        self.lbl_radar_status.pack(side="right", padx=16)

        body = ctk.CTkFrame(tab, fg_color="transparent")
        body.pack(expand=True, fill="both", padx=10, pady=(4, 10))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)
        radar_frame = ctk.CTkFrame(body, fg_color="#020704", border_width=1, border_color="#28773c")
        radar_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.radar_canvas = DragonRadarCanvas(radar_frame)
        self.radar_canvas.pack(expand=True, fill="both", padx=5, pady=5)

        list_frame = ctk.CTkFrame(body, fg_color=PANEL_BG)
        list_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ctk.CTkLabel(list_frame, text="CONTACTOS DETECTADOS", text_color=CYAN,
                     font=("Consolas", 12, "bold")).pack(anchor="w", padx=12, pady=10)
        cols = ("SSID", "Señal", "Proximidad", "CH", "Seguridad")
        self.tree_radar = ttk.Treeview(list_frame, columns=cols, show="headings", height=20)
        widths = {"SSID": 180, "Señal": 95, "Proximidad": 95, "CH": 45, "Seguridad": 115}
        for col in cols:
            self.tree_radar.heading(col, text=col)
            self.tree_radar.column(col, width=widths[col], anchor="center")
        self.tree_radar.pack(expand=True, fill="both", padx=8, pady=(0, 8))

    def _start_radar(self) -> None:
        if not self._radar_stop.is_set() and getattr(self, "_radar_thread", None) and self._radar_thread.is_alive():
            return
        self._radar_stop.clear()
        try:
            self._radar_interval_seconds = max(2.0, min(60.0, float(self.radar_interval.get() or 4)))
        except ValueError:
            self._radar_interval_seconds = 4.0
        self._radar_seen.clear()
        self._radar_started_at = time.monotonic()
        self._radar_scan_source = self.scan_source_combo.get()
        self._set_run_buttons(self.btn_radar_start, self.btn_radar_stop, True)
        self.radar_canvas.set_running(True)
        self.lbl_radar_status.configure(text="RADAR ACTIVO", text_color=RADAR_GREEN)
        self._radar_thread = threading.Thread(target=self._radar_worker, daemon=True)
        self._radar_thread.start()

    def _stop_radar(self) -> None:
        self._radar_stop.set()
        self.radar_canvas.set_running(False)
        self.btn_radar_stop.configure(state="disabled", fg_color=BUTTON_IDLE)
        self.lbl_radar_status.configure(text="RADAR DETENIENDO…", text_color=WARNING)

    def _radar_worker(self) -> None:
        try:
            while not self._radar_stop.is_set():
                results, engine = self._scan_with_source(self._radar_scan_source)
                self.scan_results = results
                self._ui_call(lambda data=results, active_engine=engine: self._update_radar(data, active_engine))
                self._radar_stop.wait(self._radar_interval_seconds)
        except Exception as exc:
            self._log(f"Radar: {exc}", "ERROR")
        finally:
            self._ui_call(self._finish_radar)

    def _finish_radar(self) -> None:
        self.radar_canvas.set_running(False)
        self._set_run_buttons(self.btn_radar_start, self.btn_radar_stop, False)
        self.lbl_radar_status.configure(text="RADAR DETENIDO", text_color=WARNING)

    def _update_radar(self, results: List[NetworkEntry], engine: str = "") -> None:
        networks = [n for n in results if n.bssid]
        self.radar_canvas.set_networks(networks)
        if hasattr(self, "spectrum_canvas"):
            self.spectrum_canvas.set_networks(networks)
        self.tree_radar.delete(*self.tree_radar.get_children())
        for network in sorted(networks, key=lambda item: parse_signal_percent(item.signal), reverse=True):
            self.tree_radar.insert("", "end", values=(
                network.ssid, network.signal or "N/A", proximity_label(network.signal),
                network.channel or "?", network.score_label,
            ))
        self.lbl_radar_status.configure(
            text=(f"RADAR ACTIVO · {len(networks)} REDES · {engine or 'INVENTARIO'} · "
                  f"{datetime.datetime.now().strftime('%H:%M:%S')}"),
            text_color=RADAR_GREEN,
        )
        bssids = {network.bssid for network in networks}
        if self._radar_started_at:
            self._radar_seen.update(bssids)
            elapsed_minutes = max((time.monotonic() - self._radar_started_at) / 60.0, 1 / 60)
            rate = len(self._radar_seen) / elapsed_minutes
        else:
            rate = 0.0
        if hasattr(self, "spectrum_metrics"):
            band24 = sum(1 for item in networks if str(item.channel).isdigit() and int(item.channel) <= 14)
            values = {
                "AP EN VISTA": str(len(networks)),
                "NUEVAS SESIÓN": str(len(self._radar_seen)),
                "NUEVAS / MIN": f"{rate:.1f}",
                "2.4 GHz": str(band24),
                "5 / 6 GHz": str(len(networks) - band24),
            }
            for key, value in values.items():
                self.spectrum_metrics[key].configure(text=value)

    # ── TAB: Analizador visual de espectro ──────────────────
    def _build_tab_spectrum(self) -> None:
        tab = self.tabs.tab("Espectro")
        header = ctk.CTkFrame(tab, fg_color=PANEL_BG, border_width=1, border_color="#28693b")
        header.pack(fill="x", padx=10, pady=(8, 4))
        self.spectrum_metrics: Dict[str, ctk.CTkLabel] = {}
        metric_colors = [RADAR_GREEN, CYAN, WARNING, "#ffe66d", "#70a1ff"]
        for index, name in enumerate(("AP EN VISTA", "NUEVAS SESIÓN", "NUEVAS / MIN", "2.4 GHz", "5 / 6 GHz")):
            card = ctk.CTkFrame(header, fg_color="#06110b")
            card.pack(side="left", expand=True, fill="x", padx=5, pady=7)
            value = ctk.CTkLabel(card, text="0", text_color=metric_colors[index],
                                 font=("Consolas", 24, "bold"))
            value.pack(pady=(7, 0))
            ctk.CTkLabel(card, text=name, text_color="#91a99a",
                         font=("Consolas", 9, "bold")).pack(pady=(0, 7))
            self.spectrum_metrics[name] = value
        self.spectrum_canvas = SpectrumCanvas(tab)
        self.spectrum_canvas.pack(expand=True, fill="both", padx=10, pady=(4, 10))

    # ── TAB: Wardriving / WiGLE ─────────────────────────────
    def _build_tab_wardrive(self) -> None:
        tab = self.tabs.tab("Mapa y Wardriving")
        controls = ctk.CTkFrame(tab, fg_color=PANEL_BG)
        controls.pack(fill="x", padx=10, pady=(8, 4))
        ctk.CTkLabel(controls, text="GPS:", text_color=CYAN).pack(side="left", padx=(10, 4))
        self.gps_source_combo = ctk.CTkComboBox(
            controls, values=GPSManager.sources(), width=300, command=lambda _: None
        )
        self.gps_source_combo.set(GPSManager.sources()[0])
        self.gps_source_combo.pack(side="left", padx=4, pady=8)
        ctk.CTkButton(controls, text="↻ GPS", width=70, command=self._refresh_gps_sources,
                      fg_color="#315463").pack(side="left", padx=4)
        self.btn_map_cache = ctk.CTkButton(
            controls, text="Precargar mapa", width=116,
            command=lambda: threading.Thread(target=self._cache_map_area, daemon=True).start(),
            fg_color="#315463",
        )
        self.btn_map_cache.pack(side="left", padx=4)
        ctk.CTkLabel(controls, text="Intervalo:").pack(side="left", padx=(12, 4))
        self.wardrive_interval = ctk.CTkEntry(controls, width=55)
        self.wardrive_interval.insert(0, "5")
        self.wardrive_interval.pack(side="left")
        self.btn_wardrive_start = ctk.CTkButton(
            controls, text="▶ INICIAR RUTA", command=self._start_wardrive,
            fg_color=BUTTON_START, width=150,
        )
        self.btn_wardrive_start.pack(side="left", padx=(14, 4))
        self.btn_wardrive_stop = ctk.CTkButton(
            controls, text="■ Finalizar", command=self._stop_wardrive,
            fg_color=BUTTON_IDLE, state="disabled", width=110,
        )
        self.btn_wardrive_stop.pack(side="left", padx=4)
        ctk.CTkButton(controls, text="Exportar WiGLE + Mapas", command=self._export_wardrive,
                      fg_color="#155f75", width=185).pack(side="right", padx=10)

        stats = ctk.CTkFrame(tab, fg_color="#06110b")
        stats.pack(fill="x", padx=10, pady=4)
        self.lbl_ward_session = ctk.CTkLabel(stats, text="SESIÓN: —", font=("Consolas", 11, "bold"), text_color=WARNING)
        self.lbl_ward_session.pack(side="left", padx=12, pady=6)
        self.lbl_ward_gps = ctk.CTkLabel(stats, text="GPS: SIN FIX", font=("Consolas", 10), text_color=DANGER)
        self.lbl_ward_gps.pack(side="left", padx=20)
        self.lbl_ward_counts = ctk.CTkLabel(
            stats, text="REDES: 0 · OBS: 0 · 0.00 km · 0.0 km/h · 0.0 nuevas/min",
            font=("Consolas", 10), text_color=RADAR_GREEN,
        )
        self.lbl_ward_counts.pack(side="right", padx=12)

        body = ctk.CTkFrame(tab, fg_color="transparent")
        body.pack(expand=True, fill="both", padx=10, pady=(4, 10))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        map_frame = ctk.CTkFrame(body, fg_color="#020704", border_width=1, border_color="#246837")
        map_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.lbl_map_detail = ctk.CTkLabel(
            map_frame, text="MAPA · mueve o amplía libremente · pulsa un punto para ver la red",
            text_color="#86aa90", font=("Consolas", 9), anchor="w",
        )
        self.lbl_map_detail.pack(fill="x", padx=9, pady=(5, 0))
        self.map_widget = None
        if MAP_WIDGET_AVAILABLE and ResponsiveMapView is not None:
            try:
                with sqlite3.connect(MAP_CACHE_DB, timeout=1.0) as map_db:
                    map_db.execute("PRAGMA journal_mode=WAL")
                    map_db.execute("PRAGMA synchronous=NORMAL")
                    map_db.execute("PRAGMA busy_timeout=1000")
                self.map_widget = ResponsiveMapView(
                    map_frame, corner_radius=8, database_path=str(MAP_CACHE_DB),
                    use_database_only=self._headless_smoke,
                )
                self.map_widget.pack(expand=True, fill="both", padx=4, pady=4)
                self.map_widget.set_position(14.6349, -90.5069)
                self.map_widget.set_zoom(12)
            except Exception as exc:
                self.map_widget = None
                self._log(f"Mapa interactivo no disponible: {exc}", "WARNING")
        if self.map_widget is None:
            fallback = tk.Canvas(map_frame, bg="#031109", highlightthickness=0)
            fallback.pack(expand=True, fill="both", padx=4, pady=4)
            fallback.create_text(300, 220, text="MAPA SIN CONEXIÓN\nLos datos GPS se guardarán y exportarán",
                                 fill=RADAR_GREEN, justify="center", font=("Consolas", 14, "bold"))

        networks_frame = ctk.CTkFrame(body, fg_color=PANEL_BG)
        networks_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ctk.CTkLabel(networks_frame, text="REDES EN LA RUTA", text_color=CYAN,
                     font=("Consolas", 12, "bold")).pack(anchor="w", padx=12, pady=10)
        cols = ("SSID", "BSSID", "RSSI", "CH", "GPS")
        self.tree_wardrive = ttk.Treeview(networks_frame, columns=cols, show="headings")
        widths = {"SSID": 155, "BSSID": 140, "RSSI": 65, "CH": 42, "GPS": 52}
        for col in cols:
            self.tree_wardrive.heading(col, text=col)
            self.tree_wardrive.column(col, width=widths[col], anchor="center")
        self.tree_wardrive.pack(expand=True, fill="both", padx=8, pady=(0, 8))

    def _refresh_gps_sources(self) -> None:
        sources = GPSManager.sources()
        self.gps_source_combo.configure(values=sources)
        if self.gps_source_combo.get() not in sources:
            self.gps_source_combo.set(sources[0])
        self._log(f"Fuentes GPS: {', '.join(sources)}", "INFO")

    def _cache_map_area(self) -> None:
        """Preload a compact OSM area with bounded requests and one DB writer."""
        if not MAP_WIDGET_AVAILABLE or requests is None:
            self._log("Cache de mapa no disponible: faltan mapa o requests.", "ERROR")
            return
        if not self._map_cache_lock.acquire(blocking=False):
            self._log("La precarga del mapa ya está en curso.", "WARNING")
            return
        fix = self.gps_manager.snapshot()
        latitude = float(fix.latitude) if fix.valid else 14.6349
        longitude = float(fix.longitude) if fix.valid else -90.5069
        radius = 0.012  # ~1.3 km north/south; compact enough for a local route.

        def set_busy(busy: bool, detail: str) -> None:
            self.btn_map_cache.configure(
                state="disabled" if busy else "normal",
                fg_color=BUTTON_IDLE if busy else "#315463",
                text="Precargando…" if busy else "Precargar mapa",
            )
            self.lbl_map_detail.configure(text=detail, text_color=WARNING if busy else "#86aa90")
            if self.map_widget is not None:
                self.map_widget.use_database_only = busy or self._headless_smoke
                if not busy:
                    try:
                        current = self.map_widget.get_position()
                        self.map_widget.set_position(*current)
                    except Exception:
                        pass

        self._ui_call(lambda: set_busy(True, "MAPA · precargando teselas sin bloquear la interfaz…"))
        self._log(
            f"Precargando mapa OSM alrededor de {latitude:.5f}, {longitude:.5f} (zoom 13-17)…",
            "INFO",
        )
        try:
            server = "https://a.tile.openstreetmap.org/{z}/{x}/{y}.png"

            def tile_xy(lat: float, lon: float, zoom: int) -> Tuple[int, int]:
                bounded_lat = max(-85.05112878, min(85.05112878, lat))
                scale = 1 << zoom
                x = int((lon + 180.0) / 360.0 * scale)
                lat_rad = math.radians(bounded_lat)
                y = int((1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * scale)
                return max(0, min(scale - 1, x)), max(0, min(scale - 1, y))

            tasks: List[Tuple[int, int, int]] = []
            for zoom in range(13, 18):
                west_x, north_y = tile_xy(latitude + radius, longitude - radius, zoom)
                east_x, south_y = tile_xy(latitude - radius, longitude + radius, zoom)
                for x in range(min(west_x, east_x), max(west_x, east_x) + 1):
                    for y in range(min(north_y, south_y), max(north_y, south_y) + 1):
                        tasks.append((zoom, x, y))

            with sqlite3.connect(MAP_CACHE_DB, timeout=3.0) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA synchronous=NORMAL")
                db.execute("PRAGMA busy_timeout=3000")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS server (url VARCHAR(300) PRIMARY KEY NOT NULL, max_zoom INTEGER NOT NULL)"
                )
                db.execute(
                    "CREATE TABLE IF NOT EXISTS tiles (zoom INTEGER NOT NULL, x INTEGER NOT NULL, "
                    "y INTEGER NOT NULL, server VARCHAR(300) NOT NULL, tile_image BLOB NOT NULL, "
                    "PRIMARY KEY (zoom, x, y, server))"
                )
                db.execute("INSERT OR IGNORE INTO server(url, max_zoom) VALUES(?, ?)", (server, 19))
                existing = {
                    (int(row[0]), int(row[1]), int(row[2]))
                    for row in db.execute(
                        "SELECT zoom, x, y FROM tiles WHERE server=? AND zoom BETWEEN 13 AND 17", (server,)
                    )
                }
                pending = [task for task in tasks if task not in existing]
                stored = 0
                failed = 0
                for index, (zoom, x, y) in enumerate(pending, 1):
                    url = server.replace("{z}", str(zoom)).replace("{x}", str(x)).replace("{y}", str(y))
                    try:
                        response = requests.get(
                            url, timeout=(3.0, 8.0),
                            headers={"User-Agent": f"WirelessAuditPro/{VERSION} offline-map"},
                        )
                        response.raise_for_status()
                        data = response.content
                        if PILImage is not None:
                            with PILImage.open(io.BytesIO(data)) as tile:
                                tile.verify()
                        db.execute(
                            "INSERT OR REPLACE INTO tiles(zoom, x, y, server, tile_image) VALUES(?, ?, ?, ?, ?)",
                            (zoom, x, y, server, data),
                        )
                        stored += 1
                    except Exception:
                        failed += 1
                    if index % 20 == 0:
                        db.commit()
                        self._log(f"Mapa offline: {index}/{len(pending)} teselas procesadas.", "INFO")
                db.commit()
            size_mb = MAP_CACHE_DB.stat().st_size / (1024 * 1024)
            total_ready = len(tasks) - failed
            level = "OK" if failed == 0 else "WARNING"
            self._log(
                f"Mapa offline listo: {total_ready}/{len(tasks)} teselas · "
                f"{stored} nuevas · {size_mb:.1f} MB",
                level,
            )
        except Exception as exc:
            self._log(f"No se pudo precargar el mapa: {exc}", "ERROR")
        finally:
            self._map_cache_lock.release()
            self._ui_call(lambda: set_busy(False, "MAPA · caché lista · pulsa un punto para ver la red"))

    def _start_wardrive(self) -> None:
        if self._wardrive_session_id is not None:
            return
        source = self.gps_source_combo.get()
        if source != "Sin GPS (solo inventario)":
            accepted = messagebox.askyesno(
                "Permiso de ubicación",
                "Wireless Audit Pro solicita usar tu ubicación para registrar la ruta y "
                "asociar coordenadas a los SSID detectados.\n\n"
                "Las coordenadas se guardan únicamente en data/wardrive.sqlite3 y en las "
                "exportaciones locales que tú generes. No se envían a ningún servidor.\n\n"
                "¿Permitir GPS durante esta sesión de wardriving?",
                parent=self,
            )
            if not accepted:
                self._log("Permiso GPS rechazado; no se inició la ruta.", "WARNING")
                return
            self._log(f"Permiso GPS aceptado para esta ruta ({source}).", "OK")
        self._wardrive_scan_source = self.scan_source_combo.get()
        self._wardrive_session_id = self.wardrive_store.begin_session(
            source, self._wardrive_scan_source
        )
        self._last_wardrive_session_id = self._wardrive_session_id
        self._wardrive_stop.clear()
        self._wardrive_markers.clear()
        self._wardrive_best_signal.clear()
        self._wardrive_track.clear()
        self._wardrive_map_track.clear()
        self._wardrive_path = None
        self._wardrive_distance_km = 0.0
        self._wardrive_started_at = time.monotonic()
        self._wardrive_seen.clear()
        self._wardrive_last_fix_at = 0.0
        self.tree_wardrive.delete(*self.tree_wardrive.get_children())
        self.gps_manager.start(source)
        self.lbl_ward_session.configure(
            text=f"SESIÓN: {self._wardrive_session_id} · GRABANDO", text_color=RADAR_GREEN
        )
        self._set_run_buttons(self.btn_wardrive_start, self.btn_wardrive_stop, True)
        try:
            self._wardrive_interval_seconds = max(2.0, min(120.0, float(self.wardrive_interval.get() or 5)))
        except ValueError:
            self._wardrive_interval_seconds = 5.0
        self._wardrive_thread = threading.Thread(target=self._wardrive_worker, daemon=True)
        self._wardrive_thread.start()
        self._log(f"Wardriving iniciado · sesión {self._wardrive_session_id} · {source}", "OK")

    def _stop_wardrive(self) -> None:
        session_id = self._wardrive_session_id
        if session_id is None:
            return
        self._wardrive_stop.set()
        self.gps_manager.stop()
        self.btn_wardrive_stop.configure(state="disabled", fg_color=BUTTON_IDLE)
        self.lbl_ward_session.configure(text=f"SESIÓN: {session_id} · DETENIENDO…", text_color=WARNING)

    def _wardrive_worker(self) -> None:
        session_id = self._wardrive_session_id
        if session_id is None:
            return
        try:
            while not self._wardrive_stop.is_set() and self._wardrive_session_id == session_id:
                networks, scan_engine = self._scan_with_source(self._wardrive_scan_source)
                if self._wardrive_stop.is_set():
                    break
                fix = self.gps_manager.snapshot()
                self.wardrive_store.add_observations(session_id, networks, fix, scan_engine)
                self.scan_results = networks
                self._ui_call(
                    lambda data=networks, gps=fix, sid=session_id, engine=scan_engine:
                    self._update_wardrive_ui(sid, data, gps, engine)
                )
                self._wardrive_stop.wait(self._wardrive_interval_seconds)
        except Exception as exc:
            self._log(f"Wardriving: {exc}", "ERROR")
        finally:
            self.gps_manager.stop()
            self.wardrive_store.end_session(session_id)
            self._ui_call(lambda sid=session_id: self._finish_wardrive(sid))

    def _finish_wardrive(self, session_id: int) -> None:
        if self._wardrive_session_id == session_id:
            self._wardrive_session_id = None
        self._set_run_buttons(self.btn_wardrive_start, self.btn_wardrive_stop, False)
        self.lbl_ward_session.configure(text=f"SESIÓN: {session_id} · FINALIZADA", text_color=WARNING)
        self._log(f"Wardriving finalizado · sesión {session_id}", "OK")

    def _update_wardrive_ui(
        self, session_id: int, networks: List[NetworkEntry], fix: GPSFix, scan_engine: str = "",
    ) -> None:
        valid_networks = [n for n in networks if n.bssid]
        if hasattr(self, "radar_canvas"):
            self.radar_canvas.set_networks(valid_networks)
        if fix.valid:
            self.lbl_ward_gps.configure(
                text=(f"GPS: {fix.latitude:.6f}, {fix.longitude:.6f} · "
                      f"±{(fix.accuracy or 0):.0f} m · SAT {fix.satellites or '—'}"),
                text_color=RADAR_GREEN,
            )
            point = (float(fix.latitude), float(fix.longitude))
            if not self._wardrive_track or point != self._wardrive_track[-1]:
                now_mono = time.monotonic()
                if self._wardrive_track:
                    previous = self._wardrive_track[-1]
                    segment_km = self._distance_km(previous, point)
                    # Ignore physically impossible GPS jumps while keeping a useful route total.
                    if segment_km <= 2.0:
                        self._wardrive_distance_km += segment_km
                        if fix.speed_kmh is None and self._wardrive_last_fix_at:
                            seconds = max(0.1, now_mono - self._wardrive_last_fix_at)
                            fix.speed_kmh = segment_km / seconds * 3600.0
                self._wardrive_last_fix_at = now_mono
                self._wardrive_track.append(point)
                self._update_map_route(point)
        else:
            self.lbl_ward_gps.configure(text="GPS: SIN FIX · inventario sin coordenadas", text_color=WARNING)

        for network in valid_networks:
            pct = parse_signal_percent(network.signal)
            iid = network.bssid.replace(":", "_")
            values = (
                network.ssid, network.bssid, f"{signal_dbm(network.signal)} dBm",
                network.channel or "?", "✓" if fix.valid else "—",
            )
            if self.tree_wardrive.exists(iid):
                self.tree_wardrive.item(iid, values=values)
            else:
                self.tree_wardrive.insert("", "end", iid=iid, values=values)
        if fix.valid:
            self._update_map_markers(valid_networks, fix)
        networks_count, observations = self.wardrive_store.counts(session_id)
        self._wardrive_seen.update(network.bssid for network in valid_networks)
        elapsed_minutes = max((time.monotonic() - self._wardrive_started_at) / 60.0, 1 / 60)
        new_rate = len(self._wardrive_seen) / elapsed_minutes
        speed = fix.speed_kmh or 0.0
        self.lbl_ward_counts.configure(
            text=(f"REDES: {networks_count} · OBS: {observations} · "
                  f"{self._wardrive_distance_km:.2f} km · {speed:.1f} km/h · {new_rate:.1f} nuevas/min · "
                  f"{scan_engine or 'INVENTARIO'}")
        )

    @staticmethod
    def _distance_km(point_a: Tuple[float, float], point_b: Tuple[float, float]) -> float:
        lat1, lon1, lat2, lon2 = map(math.radians, (*point_a, *point_b))
        dlat, dlon = lat2 - lat1, lon2 - lon1
        arc = 2 * math.asin(math.sqrt(
            math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        ))
        return 6371.0088 * arc

    def _update_map_route(self, point: Tuple[float, float]) -> None:
        if self.map_widget is None:
            return
        if not self._wardrive_map_track:
            self._wardrive_map_track.append(point)
            self.map_widget.set_position(*point)
            self.map_widget.set_zoom(17)
            return
        if self._distance_km(self._wardrive_map_track[-1], point) < MAP_MIN_TRACK_KM:
            return
        self._wardrive_map_track.append(point)
        if self._wardrive_path is None and len(self._wardrive_map_track) >= 2:
            # Pass a copy: CanvasPath owns and extends its list internally.
            self._wardrive_path = self.map_widget.set_path(
                list(self._wardrive_map_track), color=RADAR_GREEN, width=4
            )
        elif self._wardrive_path is not None:
            self._wardrive_path.add_position(*point)

    def _on_map_marker_clicked(self, marker: Any) -> None:
        data = marker.data if isinstance(getattr(marker, "data", None), dict) else {}
        self.lbl_map_detail.configure(
            text=(f"MAPA · {data.get('ssid', '<SSID oculto>')} · {data.get('bssid', '—')} · "
                  f"{data.get('rssi', '—')} dBm · CH {data.get('channel', '—')} · "
                  f"{data.get('auth', 'Desconocido')}"),
            text_color=CYAN,
        )

    def _update_map_markers(self, networks: List[NetworkEntry], fix: GPSFix) -> None:
        if self.map_widget is None or not fix.valid:
            return
        latitude, longitude = float(fix.latitude), float(fix.longitude)
        updates = 0
        for network in sorted(networks, key=lambda item: parse_signal_percent(item.signal), reverse=True):
            if updates >= MAP_UPDATES_PER_TICK:
                break
            pct = parse_signal_percent(network.signal)
            marker = self._wardrive_markers.get(network.bssid)
            if marker is not None and pct <= self._wardrive_best_signal.get(network.bssid, -1):
                continue
            if marker is None and len(self._wardrive_markers) >= MAP_MAX_MARKERS:
                continue
            marker_data = {
                "ssid": network.ssid or "<SSID oculto>", "bssid": network.bssid,
                "rssi": signal_dbm(network.signal), "channel": network.channel or "?",
                "auth": network.auth or "Desconocido",
            }
            color = DANGER if network.score < 40 else CYAN if "WPA3" in network.auth.upper() else RADAR_GREEN
            if marker is None:
                marker = self.map_widget.set_marker(
                    latitude, longitude, text=None, command=self._on_map_marker_clicked,
                    data=marker_data, marker_color_circle=color, marker_color_outside="#07150d",
                )
                self._wardrive_markers[network.bssid] = marker
            else:
                marker.data = marker_data
                marker.set_position(latitude, longitude)
            self._wardrive_best_signal[network.bssid] = pct
            updates += 1

    def _export_wardrive(self) -> None:
        session_id = self._wardrive_session_id or self._last_wardrive_session_id
        if session_id is None:
            messagebox.showinfo("Wardriving", "Todavía no existe una sesión para exportar.")
            return
        self._log(f"Exportando sesión de wardriving {session_id} en segundo plano…", "INFO")

        def worker() -> None:
            try:
                outputs = WardriveExporter.export_all(self.wardrive_store, session_id)
                self._log("Exportaciones: " + " | ".join(str(p) for p in outputs.values()), "OK")
            except Exception as exc:
                self._log(f"Exportar wardriving: {exc}", "ERROR")
                self._ui_call(lambda msg=str(exc): messagebox.showerror("Exportación", msg, parent=self))

        threading.Thread(target=worker, daemon=True).start()

    # ── TAB: Adaptador ───────────────────────────────────────
    def _build_tab_adapter(self) -> None:
        tab = self.tabs.tab("Alfa")
        top = ctk.CTkFrame(tab)
        top.pack(fill="x", padx=10, pady=8)
        ctk.CTkButton(top, text="Refrescar radios",
                      command=lambda: threading.Thread(
                          target=lambda: self._detect_adapter(force=True), daemon=True).start(),
                      width=150).pack(side="left", padx=8)
        self.btn_validate_alfa = ctk.CTkButton(
            top, text="Validar conexión Alfa", command=self._start_alfa_validation,
            width=175, fg_color="#238636",
        )
        self.btn_validate_alfa.pack(side="left", padx=5)
        ctk.CTkButton(top, text="Preparar Alfa en Kali",
                      command=self._confirm_attach_alfa,
                      width=175, fg_color="#155f75").pack(side="left", padx=5)
        ctk.CTkButton(top, text="Devolver Alfa a Windows",
                      command=lambda: threading.Thread(
                          target=lambda: AlfaWslCore.detach(self._alfa_log), daemon=True).start(),
                      width=165, fg_color="#6e4c2f").pack(side="left", padx=5)
        ctk.CTkButton(top, text="Validar radio avanzada",
                      command=lambda: threading.Thread(
                          target=lambda: AlfaWslCore.validate_monitor_injection(self._alfa_log), daemon=True).start(),
                      width=195, fg_color="#7a3030").pack(side="left", padx=5)

        self.lbl_alfa_validation = ctk.CTkLabel(
            tab, text="Validación física pendiente", text_color="#8b949e",
            font=("Consolas", 11, "bold"),
        )
        self.lbl_alfa_validation.pack(anchor="w", padx=18, pady=(0, 3))

        rf_controls = ctk.CTkFrame(tab, fg_color=PANEL_BG)
        rf_controls.pack(fill="x", padx=10, pady=(0, 5))
        ctk.CTkLabel(rf_controls, text="Dominio RF del lugar físico:", text_color=CYAN).pack(
            side="left", padx=(12, 5), pady=7
        )
        self.rf_country = ctk.CTkComboBox(
            rf_controls, values=["GT", "MX", "US", "CA", "CR", "SV", "HN", "PA", "ES"], width=75,
        )
        self.rf_country.set("GT")
        self.rf_country.pack(side="left", padx=4)
        ctk.CTkButton(
            rf_controls, text="Aplicar regulación", width=145, fg_color="#315463",
            command=lambda: threading.Thread(
                target=AlfaWslCore.set_reg_domain,
                args=(self.rf_country.get(), self._alfa_log), daemon=True,
            ).start(),
        ).pack(side="left", padx=6)
        ctk.CTkLabel(
            rf_controls,
            text="Ajusta canales y potencia permitidos por cfg80211; no fuerza valores fuera del driver.",
            text_color="#8ea898",
        ).pack(side="left", padx=10)

        # Tabla de todos los adaptadores
        ctk.CTkLabel(tab, text="Todos los adaptadores de red del sistema:",
                     font=("Segoe UI", 11), text_color="#79c0ff").pack(anchor="w", padx=12, pady=(4, 0))
        cols_a = ("Nombre", "Descripcion", "MAC", "Estado", "Velocidad")
        self.tree_adapters = ttk.Treeview(tab, columns=cols_a, show="headings", height=5)
        w_a = {"Nombre": 140, "Descripcion": 320, "MAC": 140, "Estado": 90, "Velocidad": 100}
        for c in cols_a:
            self.tree_adapters.heading(c, text=c)
            self.tree_adapters.column(c, width=w_a.get(c, 100), anchor="w")
        self.tree_adapters.pack(fill="x", padx=10, pady=(2, 8))

        sf = ctk.CTkScrollableFrame(tab)
        sf.pack(expand=True, fill="both", padx=10, pady=4)
        self.lbl_adapter_detail = ctk.CTkLabel(
            sf, text="Detectando...",
            font=("Courier New", 12), justify="left", wraplength=1000)
        self.lbl_adapter_detail.pack(anchor="w", padx=10, pady=8)
        self.alfa_console = ctk.CTkTextbox(sf, height=170, font=("Courier New", 10),
                                           fg_color="#050b08", text_color=RADAR_GREEN)
        self.alfa_console.pack(fill="x", padx=10, pady=(4, 10))
        self.alfa_console.insert("end", "La AWUS1900 se detectará automáticamente cuando la conectes.\n")

    def _detect_adapter(
        self, force: bool = False,
    ) -> Tuple[AdapterInfo, AdapterInfo, CapabilitySnapshot]:
        self._log("Detectando adaptador Wi-Fi y Alfa AWUS1900...")
        if force:
            AdapterManager.invalidate_caches()
        alfa_interface = AdapterManager.get_alfa_interface_name(force=force)
        if alfa_interface:
            self._ui_call(
                lambda name=alfa_interface: self.lbl_banner_alfa.configure(
                    text=f"  ALFA WINDOWS LISTA · {name}", text_color=RADAR_GREEN
                )
            )
        adapters = AdapterManager.list_all_adapters(force=force)
        info = AdapterManager.get_info()
        alfa_info = AdapterManager.get_alfa_info(force=force)
        self.adapter_info = info
        self._ui_call(lambda: self._update_adapter_ui(info, alfa_info, adapters))
        capabilities = self._refresh_capabilities(info, force=force)
        return info, alfa_info, capabilities

    def _start_alfa_validation(self) -> None:
        if self.btn_validate_alfa.cget("state") == "disabled":
            return
        self.btn_validate_alfa.configure(state="disabled", fg_color=BUTTON_IDLE)
        self.lbl_alfa_validation.configure(text="VALIDANDO HARDWARE PRESENTE…", text_color=CYAN)
        self._alfa_log("Validación física solicitada: descartando caché y registro persistido…", "INFO")
        threading.Thread(target=self._alfa_validation_worker, daemon=True).start()

    def _alfa_validation_worker(self) -> None:
        try:
            _info, alfa_info, capabilities = self._detect_adapter(force=True)
            detected = capabilities.alfa_present or alfa_info.is_alfa
            scan_count = 0
            if alfa_info.is_alfa and alfa_info.name:
                scan_count = sum(1 for item in ReconCore.scan(alfa_info.name) if item.bssid)
            elif capabilities.alfa_linux_interface:
                scan_count = sum(1 for item in AlfaWslCore.scan_networks() if item.bssid)
            if detected and scan_count:
                summary = f"CONECTADA Y OPERATIVA · {scan_count} BSSID detectados"
                color, level = RADAR_GREEN, "OK"
            elif detected:
                summary = "CONECTADA FÍSICAMENTE · interfaz RF sin resultados de escaneo"
                color, level = WARNING, "WARNING"
            elif capabilities.alfa_registered:
                summary = "DESCONECTADA · sólo existe el registro persistido de USBIPD"
                color, level = DANGER, "WARNING"
            else:
                summary = "NO DETECTADA FÍSICAMENTE"
                color, level = DANGER, "WARNING"
            self._alfa_log(summary, level)
            self._ui_call(lambda: self.lbl_alfa_validation.configure(text=summary, text_color=color))
        except Exception as exc:
            self._alfa_log(f"Validación física falló: {exc}", "ERROR")
            self._ui_call(lambda: self.lbl_alfa_validation.configure(
                text="ERROR DE VALIDACIÓN", text_color=DANGER,
            ))
        finally:
            self._ui_call(lambda: self.btn_validate_alfa.configure(
                state="normal", fg_color=BUTTON_START,
            ))

    def _alfa_log(self, message: str, level: str = "INFO") -> None:
        def write() -> None:
            self.alfa_console.insert("end", f"[{level}] {message}\n")
            self.alfa_console.see("end")
        self._ui_call(write)
        self._log(message, level)

    def _confirm_attach_alfa(self) -> None:
        if os.name != "nt":
            threading.Thread(target=self._attach_alfa_worker, daemon=True).start()
            return
        accepted = messagebox.askyesno(
            "Conectar Alfa a Kali",
            "Se transferirá la Alfa de Windows a Kali WSL2. Mientras esté adjunta no podrá "
            "usarse desde Windows.\n\nSi el dispositivo aún no está compartido, Windows "
            "mostrará una solicitud UAC claramente identificada para ejecutar usbipd bind.\n\n"
            "¿Continuar?",
            parent=self,
        )
        if accepted:
            threading.Thread(target=self._attach_alfa_worker, daemon=True).start()

    def _attach_alfa_worker(self) -> None:
        self._alfa_log("Preparando Alfa AWUS1900 para Kali WSL2…", "INFO")
        if AlfaWslCore.attach(self._alfa_log):
            time.sleep(2)
            AlfaWslCore.linux_probe(self._alfa_log)
        self._refresh_capabilities()

    def _probe_kali_worker(self) -> None:
        self._alfa_log("Ejecutando diagnóstico USB, interfaz y toolchain en Kali…", "INFO")
        AlfaWslCore.linux_probe(self._alfa_log)

    def _update_adapter_ui(
        self, info: AdapterInfo, alfa_info: AdapterInfo, adapters: List[Dict[str, str]]
    ) -> None:
        # Banner superior
        if alfa_info.is_alfa:
            self.lbl_banner_alfa.configure(
                text=f"  ALFA LISTA · {alfa_info.name} · {alfa_info.mac}",
                text_color="#3fb950")
        else:
            self.lbl_banner_alfa.configure(
                text="  Alfa AWUS1900 no detectada  |  " + info.name,
                text_color="#f85149")

        # Tabla de adaptadores
        self.tree_adapters.delete(*self.tree_adapters.get_children())
        for a in adapters:
            is_alfa_row, _method = AdapterManager._detect_alfa(a.get("name", ""), a.get("desc", ""))
            tag = "alfa" if is_alfa_row else "normal"
            self.tree_adapters.insert("", "end",
                values=(a["name"], a["desc"], a["mac"], a["status"], a["speed"]),
                tags=(tag,))
        self.tree_adapters.tag_configure("alfa",   foreground="#3fb950")
        self.tree_adapters.tag_configure("normal", foreground="#c9d1d9")

        lines = [
            "=" * 62,
            "  RADIO DE INTERNET:",
            "  Nombre          : " + info.name,
            "  Descripcion     : " + (info.description or "N/A"),
            "  Alfa AWUS1900   : " + (
                "También es la radio activa" if info.is_alfa
                else "Conectada como radio separada" if alfa_info.is_alfa
                else "No conectada físicamente"
            ),
            "  MAC             : " + info.mac,
            "  Estado          : " + info.state,
            "  Driver version  : " + info.driver_version,
            "  Driver fecha    : " + info.driver_date,
            "=" * 62,
            "  CONEXION ACTUAL:",
            "  SSID            : " + (info.ssid or "N/A"),
            "  BSSID AP        : " + (info.bssid or "N/A"),
            "  Radio           : " + (info.radio_type or "N/A"),
            "  Auth            : " + (info.auth or "N/A"),
            "  Cifrado         : " + (info.cipher or "N/A"),
            "  Canal           : " + (str(info.channel) if info.channel else "N/A"),
            "  Senal           : " + (signal_to_dbm(info.signal) if info.signal else "N/A"),
            "  RX              : " + (info.rx_rate or "N/A"),
            "  TX              : " + (info.tx_rate or "N/A"),
            "=" * 62,
            "  RADIO DE AUDITORÍA (ALFA):",
            "  Nombre          : " + (alfa_info.name if alfa_info.is_alfa else "NO DETECTADA"),
            "  Descripción     : " + (alfa_info.description or "N/A"),
            "  MAC             : " + (alfa_info.mac or "N/A"),
            "  Estado          : " + (alfa_info.state or "N/A"),
            "  Driver          : " + (alfa_info.driver_version or "N/A"),
            "=" * 62,
            "",
            "  NOTA MONITOR MODE WINDOWS (RTL8814AU):",
            "  Monitor anunciado : " + ("SI" if self.capabilities.monitor_advertised else "NO"),
            "  Npcap 802.11 raw  : " + ("OPERATIVO" if self.capabilities.npcap_dot11 else "NO EXPUESTO"),
            "  Linktypes         : " + self.capabilities.capture_linktypes,
            "  Alfa / USB       : " + self.capabilities.alfa_usb_state,
            "  Modulo 8814au    : " + ("LISTO" if self.capabilities.alfa_module_ready else "PENDIENTE"),
            "  Interfaz Kali    : " + (self.capabilities.alfa_linux_interface or "SIN INTERFAZ nl80211"),
            "  Kali WSL2        : " + self.capabilities.kali_state,
        ]
        self.lbl_adapter_detail.configure(text="\n".join(lines))
        self._log(
            f"Internet: {info.name} | Alfa: {alfa_info.name if alfa_info.is_alfa else 'no detectada'}",
            "OK" if alfa_info.is_alfa else "WARNING",
        )

    # ── TAB: Reconocimiento ──────────────────────────────────
    def _build_tab_recon(self) -> None:
        tab = self.tabs.tab("Reconocimiento")
        top = ctk.CTkFrame(tab)
        top.pack(fill="x", pady=8, padx=10)
        self.btn_scan = ctk.CTkButton(
            top, text="Escanear Espectro Completo",
            command=self._start_scan, width=240)
        self.btn_scan.pack(side="left", padx=8)
        self.lbl_net_count = ctk.CTkLabel(top, text="Redes: 0", text_color="#8b949e")
        self.lbl_net_count.pack(side="left", padx=8)
        self.scan_bar = ctk.CTkProgressBar(top, width=180)
        self.scan_bar.set(0)
        self.scan_bar.pack(side="left", padx=8)

        cols = ("SSID", "BSSID", "Vendor", "Senal", "Radio",
                "Canal", "Auth", "Cifrado", "Rates", "Score")
        self.tree_recon = ttk.Treeview(tab, columns=cols, show="headings")
        ws = {"SSID": 180, "BSSID": 145, "Vendor": 125, "Senal": 90,
              "Radio": 85, "Canal": 50, "Auth": 100, "Cifrado": 75,
              "Rates": 120, "Score": 130}
        for c in cols:
            self.tree_recon.heading(c, text=c)
            self.tree_recon.column(c, width=ws.get(c, 90), anchor="center")
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self.tree_recon.yview)
        self.tree_recon.configure(yscrollcommand=vsb.set)
        self.tree_recon.pack(side="left", expand=True, fill="both",
                              padx=(10, 0), pady=(0, 8))
        vsb.pack(side="left", fill="y", pady=(0, 8))
        self.tree_recon.bind("<Double-1>", self._on_net_select)
        ctk.CTkLabel(tab,
                     text="Doble clic → abre el análisis de seguridad de las redes detectadas",
                     text_color="#7ee787", font=("Segoe UI", 10)).pack()

    def _start_scan(self) -> None:
        self.btn_scan.configure(state="disabled")
        self.tree_recon.delete(*self.tree_recon.get_children())
        self.scan_bar.set(0.1)
        self._log("Escaneando espectro 802.11 completo...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        results, engine = self._scan_with_source(self.scan_source_combo.get())
        self.scan_results = results
        self._ui_call(lambda: self._replace_recon_ui(results))
        self._ui_call(lambda: self._update_radar(results, engine))

    def _replace_recon_ui(self, results: List[NetworkEntry]) -> None:
        self.tree_recon.delete(*self.tree_recon.get_children())
        self._update_recon_ui(results)

    def _update_recon_ui(self, results: List[NetworkEntry]) -> None:
        for n in results:
            if not n.bssid:
                continue
            tag = "crit" if n.score < 40 else "normal"
            self.tree_recon.insert("", "end",
                values=(n.ssid, n.bssid, n.vendor, n.signal,
                        n.radio, n.channel, n.auth, n.cipher,
                        n.rates[:30], n.score_label + " (" + str(n.score) + ")"),
                tags=(tag,))
        self.tree_recon.tag_configure("crit",   foreground="#f85149")
        self.tree_recon.tag_configure("normal", foreground="#c9d1d9")
        cnt = len([n for n in results if n.bssid])
        self.lbl_net_count.configure(text=f"Redes: {cnt}")
        self.scan_bar.set(1.0)
        self.btn_scan.configure(state="normal")
        self._log(f"Escaneo completo. {cnt} redes detectadas.", "OK")

    def _on_net_select(self, _: Any) -> None:
        sel = self.tree_recon.selection()
        if not sel:
            return
        vals = self.tree_recon.item(sel[0])["values"]
        ssid, bssid, auth = str(vals[0]), str(vals[1]), str(vals[6])
        self.tabs.set("Auditoría wireless")
        self._run_audit()
        self._log(f"Target: {ssid}  /  {bssid}", "OK")

    # ── TAB: Auditoria ───────────────────────────────────────
    def _build_tab_audit(self) -> None:
        tab = self.tabs.tab("Auditoría wireless")
        sections = ctk.CTkTabview(tab)
        sections.pack(expand=True, fill="both", padx=6, pady=4)
        sections.add("Configuración y riesgos")
        sections.add("Wifite avanzado")
        audit_tab = sections.tab("Configuración y riesgos")
        ctk.CTkButton(audit_tab, text="Analizar Seguridad de Todas las Redes",
                      command=self._run_audit, width=320).pack(pady=10)
        cols_a = ("SSID", "BSSID", "Auth", "Cifrado",
                  "Score", "Rating", "Vulnerabilidades", "Recomendacion")
        self.tree_audit = ttk.Treeview(audit_tab, columns=cols_a, show="headings")
        wa = {"SSID": 155, "BSSID": 140, "Auth": 100, "Cifrado": 75,
              "Score": 50, "Rating": 115, "Vulnerabilidades": 250, "Recomendacion": 360}
        for c in cols_a:
            self.tree_audit.heading(c, text=c)
            self.tree_audit.column(c, width=wa.get(c, 100), anchor="w")
        vsb_a = ttk.Scrollbar(audit_tab, orient="vertical", command=self.tree_audit.yview)
        hsb_a = ttk.Scrollbar(audit_tab, orient="horizontal", command=self.tree_audit.xview)
        self.tree_audit.configure(yscrollcommand=vsb_a.set, xscrollcommand=hsb_a.set)
        self.tree_audit.pack(expand=True, fill="both", padx=10, pady=(0, 0))
        hsb_a.pack(fill="x", padx=10)
        self._build_tab_wifite(sections.tab("Wifite avanzado"))

    def _run_audit(self) -> None:
        if not self.scan_results:
            messagebox.showinfo("Sin datos", "Ejecuta el escaneo en la tab Reconocimiento.")
            return
        self.tree_audit.delete(*self.tree_audit.get_children())
        for n in self.scan_results:
            if not n.bssid:
                continue
            vulns = self._get_vulns(n)
            tag = "crit" if n.score < 40 else "med" if n.score < 70 else "ok"
            self.tree_audit.insert("", "end",
                values=(n.ssid, n.bssid, n.auth, n.cipher,
                        n.score, n.score_label, vulns, n.recommendation),
                tags=(tag,))
        self.tree_audit.tag_configure("crit", foreground="#f85149")
        self.tree_audit.tag_configure("med",  foreground="#d29922")
        self.tree_audit.tag_configure("ok",   foreground="#3fb950")
        self._log("Analisis de seguridad completado.", "OK")

    @staticmethod
    def _get_vulns(n: NetworkEntry) -> str:
        v: List[str] = []
        au = n.auth.upper()
        ci = n.cipher.upper()
        if "WEP" in au:
            v.append("WEP — roto en seg")
        if "OPEN" in au or au in ("", "NINGUNO"):
            v.append("Sin auth")
        if "WPA " in au and "WPA2" not in au:
            v.append("WPA v1 obsoleto")
        if "TKIP" in ci:
            v.append("TKIP — Beck-Tews")
        if "WPA2" in au:
            v.append("Pendiente: PMF / WPS / PSK")
        if "WPA3" in au:
            v.append("Validar PMF requerido / transicion")
        if n.hidden:
            v.append("SSID oculto (trivial probe)")
        return " | ".join(v) if v else "Sin CVE criticos obvios"

    # ── TAB: Claves Wi-Fi guardadas ─────────────────────────
    def _build_tab_credentials(self) -> None:
        tab = self.tabs.tab("Claves Wi-Fi")
        notice = ctk.CTkFrame(tab, fg_color="#16120a", border_width=1, border_color="#6b531c")
        notice.pack(fill="x", padx=14, pady=(12, 6))
        ctk.CTkLabel(
            notice,
            text="CREDENCIALES GUARDADAS EN ESTE EQUIPO",
            font=("Segoe UI", 14, "bold"), text_color=WARNING,
        ).pack(anchor="w", padx=16, pady=(10, 2))
        ctk.CTkLabel(
            notice,
            text=(
                "Las redes abiertas y Enterprise se identifican sin simular una clave. "
                "Cada PSK se revela con confirmación y nunca se escribe en logs ni reportes."
            ),
            text_color="#d8c99d",
        ).pack(anchor="w", padx=16, pady=(0, 3))
        if os.name == "nt":
            privilege_text = (
                "Permiso actual: administrador"
                if WifiCredentialCore.is_windows_admin()
                else "Permiso actual: estándar · Windows solicitará UAC sólo al mostrar una PSK"
            )
        else:
            privilege_text = "Permiso actual: sesión Linux · NetworkManager controla el acceso"
        self.lbl_credentials_privilege = ctk.CTkLabel(
            notice, text=privilege_text, text_color="#9fb8aa",
        )
        self.lbl_credentials_privilege.pack(anchor="w", padx=16, pady=(0, 10))

        controls = ctk.CTkFrame(tab, fg_color="transparent")
        controls.pack(fill="x", padx=14, pady=6)
        ctk.CTkButton(
            controls, text="Actualizar perfiles", width=160, fg_color="#155f75",
            command=self._refresh_credentials,
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            controls, text="Mostrar selección", width=160, fg_color="#7a3030",
            command=self._reveal_selected_credential,
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            controls, text="Ocultar todo", width=130, fg_color="#4b5563",
            command=self._hide_credentials,
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            controls, text="Copiar 30 segundos", width=170, fg_color="#315463",
            command=self._copy_selected_credential,
        ).pack(side="left", padx=5)
        self.lbl_credentials_status = ctk.CTkLabel(
            controls, text="Sin consultar", text_color="#8b949e"
        )
        self.lbl_credentials_status.pack(side="right", padx=10)

        cols = ("Perfil", "Seguridad", "Clave", "Estado")
        self.tree_credentials = ttk.Treeview(tab, columns=cols, show="headings")
        widths = {"Perfil": 280, "Seguridad": 180, "Clave": 340, "Estado": 220}
        for col in cols:
            self.tree_credentials.heading(col, text=col)
            self.tree_credentials.column(col, width=widths[col], anchor="w")
        self.tree_credentials.pack(expand=True, fill="both", padx=14, pady=(4, 14))
        self._credential_iid_to_profile: Dict[str, str] = {}

    def _refresh_credentials(self) -> None:
        self.lbl_credentials_status.configure(text="Consultando…", text_color=CYAN)
        self._credential_passwords.clear()
        self._credential_profiles.clear()
        self._credential_visible_profile = ""

        def worker() -> None:
            try:
                profiles = WifiCredentialCore.list_profiles()
                self._ui_call(lambda: self._update_credentials(profiles))
            except Exception as exc:
                self._ui_call(lambda: self.lbl_credentials_status.configure(
                    text="Error de lectura", text_color=DANGER
                ))
                self._log(f"Perfiles Wi-Fi: {exc}", "ERROR")

        threading.Thread(target=worker, daemon=True).start()

    def _update_credentials(self, profiles: List[SavedWifiProfile]) -> None:
        self.tree_credentials.delete(*self.tree_credentials.get_children())
        self._credential_iid_to_profile.clear()
        self._credential_profiles.clear()
        for profile in profiles:
            iid = "wifi_" + hashlib.sha256(profile.name.encode("utf-8")).hexdigest()[:16]
            self._credential_iid_to_profile[iid] = profile.name
            self._credential_profiles[profile.name] = profile
            key_display, state_display, tag = self._masked_credential_state(profile)
            self.tree_credentials.insert(
                "", "end", iid=iid,
                values=(profile.name, profile.auth, key_display, state_display),
                tags=(tag,),
            )
        self.tree_credentials.tag_configure("saved", foreground="#f0d98a")
        self.tree_credentials.tag_configure("open", foreground="#72d49b")
        self.tree_credentials.tag_configure("enterprise", foreground="#75bfff")
        self.tree_credentials.tag_configure("unavailable", foreground="#9aa4ad")
        self.lbl_credentials_status.configure(
            text=f"{len(profiles)} perfiles · PSK visibles: 0", text_color=RADAR_GREEN
        )
        self._log(f"Perfiles Wi-Fi guardados inventariados: {len(profiles)}.", "OK")

    @staticmethod
    def _masked_credential_state(profile: SavedWifiProfile) -> Tuple[str, str, str]:
        if profile.recoverable:
            return "••••••••", f"{profile.key_kind} · oculta", "saved"
        if profile.key_kind == "Red abierta":
            return "No aplica", "Red abierta · sin PSK", "open"
        if profile.key_kind == "Credenciales 802.1X":
            return "No aplica", "Enterprise · sin PSK compartida", "enterprise"
        if profile.key_kind == "PSK no guardada":
            return "No guardada", profile.key_kind, "unavailable"
        if profile.key_kind == "Sin PSK (OWE)":
            return "No aplica", "OWE · cifrada sin PSK", "open"
        return "No disponible", profile.key_kind, "unavailable"

    def _selected_credential_profile(self) -> str:
        selection = self.tree_credentials.selection()
        return self._credential_iid_to_profile.get(selection[0], "") if selection else ""

    def _reveal_selected_credential(self) -> None:
        profile = self._selected_credential_profile()
        if not profile:
            messagebox.showinfo("Credenciales Wi-Fi", "Selecciona primero un perfil.", parent=self)
            return
        metadata = self._credential_profiles.get(profile)
        if metadata is None:
            messagebox.showinfo(
                "Credenciales Wi-Fi", "Actualiza la lista de perfiles e inténtalo de nuevo.", parent=self
            )
            return
        if not metadata.recoverable:
            if metadata.key_kind == "Red abierta":
                detail = "Es una red abierta; no utiliza contraseña PSK."
            elif metadata.key_kind == "Credenciales 802.1X":
                detail = "Es una red Enterprise/802.1X; no tiene una PSK compartida almacenada."
            elif metadata.key_kind == "PSK no guardada":
                detail = "El perfil no conserva una PSK en este equipo."
            elif metadata.key_kind == "Sin PSK (OWE)":
                detail = "Es una red OWE; cifra el enlace, pero no utiliza una PSK compartida."
            else:
                detail = "Este perfil no expone una PSK recuperable."
            messagebox.showinfo("Credenciales Wi-Fi", detail, parent=self)
            return

        if os.name == "nt" and not WifiCredentialCore.is_windows_admin():
            accepted = messagebox.askyesno(
                "Permiso de Windows requerido",
                (
                    f"Para mostrar la PSK guardada de “{profile}”, Windows requiere permiso "
                    "de administrador.\n\n¿Reabrir Wireless Audit Pro con UAC?"
                ),
                parent=self,
            )
            if accepted:
                self._restart_for_credentials_as_admin()
            return

        accepted = messagebox.askyesno(
            "Mostrar clave Wi-Fi",
            f"¿Mostrar temporalmente la clave guardada del perfil “{profile}”?",
            parent=self,
        )
        if not accepted:
            return
        self.lbl_credentials_status.configure(text="Solicitando clave…", text_color=CYAN)

        def worker() -> None:
            ok, value = WifiCredentialCore.reveal(profile)
            if ok:
                self._credential_passwords[profile] = value
                self._ui_call(lambda: self._show_credential_value(profile, value))
            else:
                self._ui_call(lambda: self.lbl_credentials_status.configure(
                    text="Clave no accesible", text_color=WARNING
                ))
                self._ui_call(lambda: messagebox.showwarning(
                    "Credenciales Wi-Fi", value, parent=self
                ))

        threading.Thread(target=worker, daemon=True).start()

    def _restart_for_credentials_as_admin(self) -> None:
        """Request a deliberate UAC elevation without spawning a console window."""
        if os.name != "nt":
            return
        try:
            import ctypes

            executable = Path(sys.executable).resolve()
            if getattr(sys, "frozen", False):
                arguments = ["--open-credentials"]
            else:
                gui_executable = executable.with_name(
                    "pythonw.exe" if executable.name.lower() == "python.exe" else "pyw.exe"
                )
                if executable.name.lower() in ("python.exe", "py.exe") and gui_executable.exists():
                    executable = gui_executable
                arguments = [str(Path(__file__).resolve()), "--open-credentials"]
            result = int(ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                str(executable),
                subprocess.list2cmdline(arguments),
                str(BASE_DIR),
                1,
            ))
            if result <= 32:
                self.lbl_credentials_status.configure(text="UAC cancelado", text_color=WARNING)
                messagebox.showwarning(
                    "Credenciales Wi-Fi",
                    "Windows no concedió el permiso de administrador.",
                    parent=self,
                )
                return
            self.after(250, self._on_close)
        except Exception as exc:
            self.lbl_credentials_status.configure(text="No se pudo solicitar UAC", text_color=DANGER)
            messagebox.showerror(
                "Credenciales Wi-Fi",
                f"No se pudo reabrir la aplicación como administrador: {exc}",
                parent=self,
            )

    def _show_credential_value(self, profile: str, password: str) -> None:
        self._hide_credentials()
        iid = next((key for key, value in self._credential_iid_to_profile.items() if value == profile), "")
        if iid and self.tree_credentials.exists(iid):
            values = list(self.tree_credentials.item(iid, "values"))
            values[2] = password
            values[3] = "Visible temporalmente"
            self.tree_credentials.item(iid, values=values)
            self._credential_visible_profile = profile
        self.lbl_credentials_status.configure(
            text=f"{len(self._credential_iid_to_profile)} perfiles · claves en memoria: {len(self._credential_passwords)}",
            text_color=WARNING,
        )

    def _hide_credentials(self) -> None:
        for iid in self.tree_credentials.get_children():
            values = list(self.tree_credentials.item(iid, "values"))
            if len(values) >= 4:
                profile_name = self._credential_iid_to_profile.get(iid, "")
                metadata = self._credential_profiles.get(profile_name)
                if metadata is not None:
                    values[2], values[3], tag = self._masked_credential_state(metadata)
                    self.tree_credentials.item(iid, values=values, tags=(tag,))
        self._credential_visible_profile = ""

    def _copy_selected_credential(self) -> None:
        profile = self._selected_credential_profile()
        password = self._credential_passwords.get(profile, "")
        if not profile or not password:
            messagebox.showinfo(
                "Credenciales Wi-Fi", "Primero revela la clave del perfil seleccionado.", parent=self
            )
            return
        self.clipboard_clear()
        self.clipboard_append(password)
        self.update_idletasks()
        self.lbl_credentials_status.configure(text="Clave copiada; borrado en 30 s", text_color=WARNING)

        def clear_if_unchanged(secret: str = password) -> None:
            try:
                if self.clipboard_get() == secret:
                    self.clipboard_clear()
                    self.lbl_credentials_status.configure(text="Portapapeles limpiado", text_color=RADAR_GREEN)
            except Exception:
                pass

        self.after(30_000, clear_if_unchanged)

    # ── TAB: Captura ─────────────────────────────────────────
    def _build_tab_capture(self) -> None:
        tab = self.tabs.tab("Captura")
        f = ctk.CTkFrame(tab)
        f.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(f, text="Interfaz tshark:").grid(row=0, column=0, padx=10, sticky="e")
        self.combo_iface = ctk.CTkComboBox(f, values=["Cargar interfaces..."], width=320)
        self.combo_iface.grid(row=0, column=1, padx=10, pady=8, sticky="w")
        ctk.CTkButton(f, text="Refrescar", width=90,
                      command=self._load_ifaces).grid(row=0, column=2, padx=4)
        ctk.CTkLabel(f, text="Motor:").grid(row=0, column=3, padx=(18, 4), sticky="e")
        self.capture_engine = ctk.CTkComboBox(
            f, values=["Windows / TShark", "Kali WSL2 / Alfa"], width=180,
            command=lambda _: self._load_ifaces(),
        )
        self.capture_engine.grid(row=0, column=4, padx=6, pady=8, sticky="w")

        ctk.CTkLabel(f, text="BSSID target:").grid(row=1, column=0, padx=10, sticky="e")
        self.entry_cap_bssid = ctk.CTkEntry(f, width=180,
                                             placeholder_text="AA:BB:CC:DD:EE:FF")
        self.entry_cap_bssid.grid(row=1, column=1, padx=10, pady=8, sticky="w")

        ctk.CTkLabel(f, text="Duracion (seg):").grid(row=2, column=0, padx=10, sticky="e")
        self.entry_cap_time = ctk.CTkEntry(f, width=80, placeholder_text="60")
        self.entry_cap_time.grid(row=2, column=1, padx=10, sticky="w")

        self.lbl_cap_out = ctk.CTkLabel(f, text="Salida: captures/auto.pcapng",
                                         text_color="#8b949e")
        self.lbl_cap_out.grid(row=3, column=0, columnspan=3, padx=10, pady=4, sticky="w")

        bf = ctk.CTkFrame(f, fg_color="transparent")
        bf.grid(row=4, column=0, columnspan=3, pady=12)
        self.btn_cap_start = ctk.CTkButton(bf, text="Iniciar Captura",
                                            command=self._start_capture,
                                            fg_color="#005b96")
        self.btn_cap_start.pack(side="left", padx=8)
        self.btn_cap_stop = ctk.CTkButton(bf, text="Detener",
                                           command=lambda: self._request_stop(
                                               "capture", self.btn_cap_stop),
                                           fg_color=BUTTON_IDLE, state="disabled", width=100)
        self.btn_cap_stop.pack(side="left", padx=8)

        self.cap_console = ctk.CTkTextbox(tab, font=("Courier New", 11), text_color="#79c0ff")
        self.cap_console.pack(expand=True, fill="both", padx=20, pady=(0, 10))

    def _load_ifaces(self) -> None:
        engine = self.capture_engine.get()
        self.combo_iface.set("Consultando sin bloquear…")

        def worker() -> None:
            ifaces = AlfaWslCore.list_interfaces() if engine.startswith("Kali") else CaptureCore.list_interfaces()

            def update() -> None:
                self.combo_iface.configure(values=ifaces)
                if ifaces:
                    self.combo_iface.set(ifaces[0])

            self._ui_call(update)

        threading.Thread(target=worker, daemon=True).start()

    def _fill_capture(self, bssid: str) -> None:
        self.entry_cap_bssid.delete(0, "end")
        self.entry_cap_bssid.insert(0, bssid)

    def _start_capture(self) -> None:
        iface = self.combo_iface.get().split(":")[0].strip()
        bssid = clamp_str(self.entry_cap_bssid.get().strip(), 17)
        raw_t = self.entry_cap_time.get().strip()
        timeout = int(raw_t) if raw_t.isdigit() else 60
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        engine = self.capture_engine.get()
        suffix = "kali" if engine.startswith("Kali") else "windows"
        out = CAPTURE_DIR / ("cap_" + suffix + "_" + bssid.replace(":", "")[:12] + "_" + ts + ".pcapng")
        self._cap_out_file = out
        self.lbl_cap_out.configure(text="Salida: " + str(out))
        self._stop["capture"].clear()
        self._set_run_buttons(
            self.btn_cap_start, self.btn_cap_stop, True,
            start_color="#005b96", stop_color=BUTTON_STOP,
        )
        self.cap_console.delete("1.0", "end")

        def _log(msg: str, lvl: str = "INFO") -> None:
            self._append_text(self.cap_console, msg + "\n")

        def _worker() -> None:
            if engine.startswith("Kali"):
                ok = AlfaWslCore.capture(iface, out, timeout, self._stop["capture"], _log)
            else:
                ok = CaptureCore.capture(iface, out, bssid, timeout,
                                         self._stop["capture"], _log)
            if ok:
                summary = CaptureAnalysisCore.analyze(out)
                self.last_capture_summary = summary
                _log(
                    f"[ANÁLISIS] frames={summary.frames} · beacons={summary.beacons} · "
                    f"probes={summary.probes} · EAPOL={summary.eapol} · PMKID={summary.pmkid} · "
                    f"SHA256={summary.sha256}",
                    "OK" if summary.valid else "WARNING",
                )
            msg = "Captura exitosa" if ok else "Captura fallida o cancelada"
            self._ui_call(lambda: self.cap_console.insert("end", "\n" + msg + "\n"))
            self._ui_call(lambda: self._set_run_buttons(
                self.btn_cap_start, self.btn_cap_stop, False, start_color="#005b96"
            ))
            self._log(msg, "OK" if ok else "ERROR")

        threading.Thread(target=_worker, daemon=True).start()

    # ── TAB: Cracking ────────────────────────────────────────
    def _build_tab_crack(self) -> None:
        tab = self.tabs.tab("Cracking")
        f = ctk.CTkFrame(tab)
        f.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(f, text="Archivo .cap/.hccapx:").grid(row=0, column=0, padx=10, sticky="e")
        ctk.CTkButton(f, text="Seleccionar", command=self._load_crack_cap,
                      width=130, fg_color="#005b96").grid(row=0, column=1, padx=10, pady=8, sticky="w")
        self.lbl_crack_cap = ctk.CTkLabel(f, text="Ninguno", text_color="#8b949e")
        self.lbl_crack_cap.grid(row=0, column=2, padx=4, sticky="w")

        ctk.CTkLabel(f, text="Diccionario:").grid(row=1, column=0, padx=10, sticky="e")
        ctk.CTkButton(f, text="Seleccionar", command=self._load_crack_wl,
                      width=130, fg_color="#005b96").grid(row=1, column=1, padx=10, pady=8, sticky="w")
        self.lbl_crack_wl = ctk.CTkLabel(f, text="Ninguno", text_color="#8b949e")
        self.lbl_crack_wl.grid(row=1, column=2, padx=4, sticky="w")

        ctk.CTkLabel(f, text="BSSID:").grid(row=2, column=0, padx=10, sticky="e")
        self.entry_crack_bssid = ctk.CTkEntry(f, width=180,
                                               placeholder_text="AA:BB:CC:DD:EE:FF")
        self.entry_crack_bssid.grid(row=2, column=1, padx=10, pady=8, sticky="w")

        ctk.CTkLabel(f, text="Motor:").grid(row=3, column=0, padx=10, sticky="e")
        self.crack_engine = ctk.CTkComboBox(
            f, values=["aircrack-ng", "hashcat -m22000", "hashcat -m2500"], width=220)
        self.crack_engine.grid(row=3, column=1, padx=10, pady=8, sticky="w")

        bf = ctk.CTkFrame(f, fg_color="transparent")
        bf.grid(row=4, column=0, columnspan=3, pady=12)
        self.btn_crack_start = ctk.CTkButton(bf, text="Iniciar Cracking",
                                              command=self._start_crack,
                                              fg_color="#b3261e", hover_color="#8c1d18")
        self.btn_crack_start.pack(side="left", padx=8)
        self.btn_crack_stop = ctk.CTkButton(
            bf, text="Detener",
            command=lambda: self._request_stop("crack", self.btn_crack_stop),
            fg_color=BUTTON_IDLE, state="disabled", width=100,
        )
        self.btn_crack_stop.pack(side="left", padx=8)
        ctk.CTkButton(bf, text="Analizar / convertir 22000",
                      command=self._analyze_crack_capture,
                      fg_color="#155f75", width=205).pack(side="left", padx=8)

        self.crack_console = ctk.CTkTextbox(tab, font=("Courier New", 11), text_color="#ff7b72")
        self.crack_console.pack(expand=True, fill="both", padx=20, pady=(0, 10))

    def _load_crack_cap(self) -> None:
        fp = filedialog.askopenfilename(
            filetypes=[("Capture", "*.cap *.pcap *.pcapng *.hccapx *.22000"), ("All", "*.*")])
        if fp:
            self._crack_cap = Path(fp)
            self.lbl_crack_cap.configure(text=os.path.basename(fp), text_color="#7ee787")

    def _load_crack_wl(self) -> None:
        fp = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if fp:
            self._crack_wordlist = Path(fp)
            self.lbl_crack_wl.configure(text=os.path.basename(fp), text_color="#7ee787")

    def _fill_crack(self, bssid: str) -> None:
        self.entry_crack_bssid.delete(0, "end")
        self.entry_crack_bssid.insert(0, bssid)

    def _analyze_crack_capture(self) -> None:
        if not self._crack_cap:
            messagebox.showwarning("Captura", "Selecciona primero un PCAP/PCAPNG.")
            return
        path = self._crack_cap
        self.crack_console.delete("1.0", "end")

        def worker() -> None:
            summary = CaptureAnalysisCore.analyze(path)
            self.last_capture_summary = summary
            self._append_text(
                self.crack_console,
                "ANÁLISIS DE EVIDENCIA\n"
                f"Archivo : {summary.path}\nTamaño  : {summary.size} bytes\n"
                f"SHA-256 : {summary.sha256}\nFrames  : {summary.frames}\n"
                f"Beacons : {summary.beacons}\nProbes  : {summary.probes}\n"
                f"Deauth  : {summary.deauth}\nEAPOL   : {summary.eapol}\n"
                f"WPS     : {summary.wps}\nPMKID   : {summary.pmkid}\n\n",
            )
            CaptureAnalysisCore.convert_22000(
                path, lambda msg, lvl="INFO": self._append_text(self.crack_console, f"[{lvl}] {msg}\n")
            )
        threading.Thread(target=worker, daemon=True).start()

    def _start_crack(self) -> None:
        if not self._crack_cap or not self._crack_wordlist:
            messagebox.showwarning("Incompleto", "Selecciona capture y diccionario.")
            return
        self._stop["crack"].clear()
        self._set_run_buttons(
            self.btn_crack_start, self.btn_crack_stop, True,
            start_color="#b3261e", stop_color=BUTTON_STOP,
        )
        self.crack_console.delete("1.0", "end")
        engine = self.crack_engine.get()
        bssid  = clamp_str(self.entry_crack_bssid.get().strip(), 17)

        def _log(msg: str, lvl: str = "INFO") -> None:
            self._append_text(self.crack_console, msg + "\n")

        def _worker() -> None:
            found: Optional[str] = None
            if "aircrack" in engine:
                found = CrackCore.aircrack(
                    self._crack_cap, self._crack_wordlist,  # type: ignore
                    bssid, _log, self._stop["crack"])
            else:
                mode = 22000 if "22000" in engine else 2500
                CrackCore.hashcat(
                    self._crack_cap, self._crack_wordlist,  # type: ignore
                    mode, _log, self._stop["crack"])
            msg = ("\nKEY ENCONTRADA: " + found + "\n") if found else "\n[-] Agotado.\n"
            self._ui_call(lambda: self.crack_console.insert("end", msg))
            self._ui_call(lambda: self._set_run_buttons(
                self.btn_crack_start, self.btn_crack_stop, False, start_color="#b3261e"
            ))
            if found:
                self._log("Crack exitoso: " + found, "CRITICAL")

        threading.Thread(target=_worker, daemon=True).start()

    # ── TAB: Diccionario (netsh) ─────────────────────────────
    def _build_tab_brute(self) -> None:
        tab = self.tabs.tab("Diccionario")
        f = ctk.CTkFrame(tab)
        f.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(f, text="Target SSID:").grid(row=0, column=0, padx=10, sticky="e")
        self.entry_brute_ssid = ctk.CTkEntry(f, width=260, placeholder_text="SSID del target")
        self.entry_brute_ssid.grid(row=0, column=1, padx=10, pady=8, sticky="w")

        ctk.CTkLabel(f, text="Auth tipo:").grid(row=1, column=0, padx=10, sticky="e")
        self.lbl_brute_auth_val = ctk.CTkLabel(f, text="—", text_color="#79c0ff")
        self.lbl_brute_auth_val.grid(row=1, column=1, padx=10, sticky="w")

        ctk.CTkLabel(f, text="Diccionario:").grid(row=2, column=0, padx=10, sticky="e")
        ctk.CTkButton(f, text="Seleccionar", command=self._load_brute_wl,
                      width=130, fg_color="#005b96").grid(row=2, column=1, padx=10, pady=8, sticky="w")
        self.lbl_brute_wl = ctk.CTkLabel(f, text="Ninguno", text_color="#8b949e")
        self.lbl_brute_wl.grid(row=2, column=2, padx=4, sticky="w")

        bf = ctk.CTkFrame(f, fg_color="transparent")
        bf.grid(row=3, column=0, columnspan=3, pady=12)
        self.btn_brute_start = ctk.CTkButton(bf, text="Iniciar Diccionario (netsh)",
                                              command=self._start_brute,
                                              fg_color="#b3261e", hover_color="#8c1d18")
        self.btn_brute_start.pack(side="left", padx=8)
        self.btn_brute_stop = ctk.CTkButton(bf, text="Detener", command=self._stop_brute,
                                             fg_color="#6e6e6e", state="disabled", width=100)
        self.btn_brute_stop.pack(side="left", padx=8)

        self.brute_console = ctk.CTkTextbox(tab, font=("Courier New", 11), text_color="#ff7b72")
        self.brute_console.pack(expand=True, fill="both", padx=20, pady=(0, 10))

    def _fill_brute(self, ssid: str, auth: str) -> None:
        self.entry_brute_ssid.delete(0, "end")
        self.entry_brute_ssid.insert(0, clamp_str(ssid, MAX_SSID_LENGTH))
        self._brute_auth = auth
        self.lbl_brute_auth_val.configure(text=auth)

    def _load_brute_wl(self) -> None:
        fp = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if fp:
            self._brute_wordlist = Path(fp)
            self.lbl_brute_wl.configure(text=os.path.basename(fp), text_color="#7ee787")

    def _start_brute(self) -> None:
        ssid = clamp_str(self.entry_brute_ssid.get().strip(), MAX_SSID_LENGTH)
        if not ssid or not self._brute_wordlist:
            messagebox.showwarning("Incompleto", "SSID y diccionario son obligatorios.")
            return
        self._brute_running = True
        self._set_run_buttons(
            self.btn_brute_start, self.btn_brute_stop, True,
            start_color="#b3261e", stop_color=BUTTON_STOP,
        )
        self.brute_console.delete("1.0", "end")
        self.brute_console.insert("end",
            "[*] Target: " + ssid + "\n[*] Dict: " + str(self._brute_wordlist) + "\n\n")
        threading.Thread(target=self._brute_worker,
                         args=(ssid, self._brute_wordlist, self._brute_auth),
                         daemon=True).start()

    def _stop_brute(self) -> None:
        self._brute_running = False
        self.btn_brute_stop.configure(state="disabled", fg_color=BUTTON_IDLE)
        self.brute_console.insert("end", "\n[!] Detenido.\n")

    def _brute_worker(self, ssid: str, wl: Path, auth: str) -> None:
        found = False
        count = 0
        try:
            with open(wl, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if not self._brute_running:
                        break
                    pwd = line.strip()
                    if len(pwd) < 8:
                        continue
                    count += 1
                    masked = pwd[:1] + ("*" * max(6, len(pwd) - 2)) + pwd[-1:]
                    self._append_text(self.brute_console, "[" + str(count) + "] " + masked + "\n")
                    if AttackCore.test_credential(ssid, pwd, auth):
                        self._append_text(self.brute_console,
                            "\n" + "=" * 50 + "\n"
                            "CREDENCIAL VALIDA\n"
                            "  SSID     : " + ssid + "\n"
                            "  PASSWORD : " + masked + "\n"
                            + "=" * 50 + "\n")
                        self._log("Credencial válida encontrada para " + ssid + " (valor enmascarado)", "CRITICAL")
                        found = True
                        break
        except Exception as exc:
            self._append_text(self.brute_console, "[-] Error: " + str(exc) + "\n")
        if not found and self._brute_running:
            self._append_text(self.brute_console, "\n[-] Diccionario agotado.\n")
        self._ui_call(self._reset_brute)

    def _reset_brute(self) -> None:
        self._brute_running = False
        self._set_run_buttons(
            self.btn_brute_start, self.btn_brute_stop, False, start_color="#b3261e"
        )

    # ── TAB: Wifite ──────────────────────────────────────────
    def _build_tab_wifite(self, parent: Optional[Any] = None) -> None:
        tab = parent if parent is not None else self.tabs.tab("Wifite")
        header = ctk.CTkFrame(tab, fg_color="#07140d", border_width=1, border_color="#256f37")
        header.pack(fill="x", padx=12, pady=(10, 5))
        ctk.CTkLabel(
            header, text="WIFITE · MOTOR INTEGRADO",
            font=("Segoe UI", 16, "bold"), text_color=RADAR_GREEN,
        ).pack(side="left", padx=16, pady=10)
        self.lbl_wifite_status = ctk.CTkLabel(
            header, text=WifiteCore.engine_name() + " · sin verificar", text_color="#8b949e"
        )
        self.lbl_wifite_status.pack(side="right", padx=16)

        config = ctk.CTkFrame(tab)
        config.pack(fill="x", padx=12, pady=5)
        ctk.CTkLabel(config, text="Interfaz:").grid(row=0, column=0, padx=(12, 4), pady=7, sticky="e")
        self.wifite_iface = ctk.CTkComboBox(config, values=["Cargar interfaz…"], width=200)
        self.wifite_iface.grid(row=0, column=1, padx=4, pady=7, sticky="w")
        ctk.CTkButton(
            config, text="Refrescar", width=85, command=self._refresh_wifite_interfaces,
            fg_color="#315463",
        ).grid(row=0, column=2, padx=4)
        ctk.CTkLabel(config, text="Modo:").grid(row=0, column=3, padx=(16, 4), sticky="e")
        self.wifite_mode = ctk.CTkComboBox(config, values=list(WifiteCore.MODES), width=145)
        self.wifite_mode.set("WPA/WPA2")
        self.wifite_mode.grid(row=0, column=4, padx=4)
        ctk.CTkLabel(config, text="Escaneo s:").grid(row=0, column=5, padx=(16, 4), sticky="e")
        self.wifite_scan_time = ctk.CTkEntry(config, width=58)
        self.wifite_scan_time.insert(0, "30")
        self.wifite_scan_time.grid(row=0, column=6, padx=4)
        ctk.CTkLabel(config, text="Señal mín:").grid(row=0, column=7, padx=(16, 4), sticky="e")
        self.wifite_power = ctk.CTkEntry(config, width=58)
        self.wifite_power.insert(0, "45")
        self.wifite_power.grid(row=0, column=8, padx=4)
        ctk.CTkLabel(config, text="Targets:").grid(row=0, column=9, padx=(16, 4), sticky="e")
        self.wifite_targets = ctk.CTkEntry(config, width=48)
        self.wifite_targets.insert(0, "1")
        self.wifite_targets.grid(row=0, column=10, padx=(4, 12))

        ctk.CTkLabel(config, text="BSSID opcional:").grid(row=1, column=0, padx=(12, 4), pady=7, sticky="e")
        self.wifite_bssid = ctk.CTkEntry(config, width=200, placeholder_text="AA:BB:CC:DD:EE:FF")
        self.wifite_bssid.grid(row=1, column=1, padx=4, pady=7, sticky="w")
        ctk.CTkButton(
            config, text="Diccionario", width=105, command=self._select_wifite_wordlist,
            fg_color="#315463",
        ).grid(row=1, column=2, padx=4)
        self.lbl_wifite_wordlist = ctk.CTkLabel(config, text="Predeterminado de Wifite", text_color="#8b949e")
        self.lbl_wifite_wordlist.grid(row=1, column=3, columnspan=2, padx=6, sticky="w")

        self.wifite_passive = ctk.BooleanVar(value=True)
        self.wifite_kill = ctk.BooleanVar(value=False)
        self.wifite_random_mac = ctk.BooleanVar(value=False)
        self.wifite_ignore_cracked = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(config, text="Sin deauth (pasivo)", variable=self.wifite_passive).grid(
            row=1, column=5, columnspan=2, padx=6, sticky="w"
        )
        ctk.CTkCheckBox(config, text="Detener conflictos", variable=self.wifite_kill).grid(
            row=1, column=7, padx=6, sticky="w"
        )
        ctk.CTkCheckBox(config, text="MAC aleatoria", variable=self.wifite_random_mac).grid(
            row=1, column=8, padx=6, sticky="w"
        )
        ctk.CTkCheckBox(config, text="Omitir crackeadas", variable=self.wifite_ignore_cracked).grid(
            row=1, column=9, columnspan=2, padx=6, sticky="w"
        )

        actions = ctk.CTkFrame(tab, fg_color="transparent")
        actions.pack(fill="x", padx=12, pady=5)
        self.btn_wifite_start = ctk.CTkButton(
            actions, text="▶ Iniciar Wifite", width=155, fg_color="#238636",
            command=self._start_wifite,
        )
        self.btn_wifite_start.pack(side="left", padx=5)
        self.btn_wifite_stop = ctk.CTkButton(
            actions, text="■ Detener", width=105, fg_color=BUTTON_IDLE, state="disabled",
            command=lambda: self._request_stop(
                "wifite", self.btn_wifite_stop, self.lbl_wifite_status),
        )
        self.btn_wifite_stop.pack(side="left", padx=5)
        ctk.CTkButton(
            actions, text="Ver resultados crackeados", width=205, fg_color="#6b4f1d",
            command=self._show_wifite_cracked,
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            actions, text="Verificar / instalar", width=170, fg_color="#155f75",
            command=self._install_wifite,
        ).pack(side="left", padx=5)

        self.wifite_console = ctk.CTkTextbox(
            tab, font=("Courier New", 11), fg_color="#030805", text_color=RADAR_GREEN
        )
        self.wifite_console.pack(expand=True, fill="both", padx=12, pady=(4, 10))
        self.wifite_console.insert(
            "end", "Wifite se ejecuta dentro de esta consola. En Windows usa Kali WSL2; en Linux usa el motor nativo.\n"
        )

    def _refresh_wifite_interfaces(self) -> None:
        self.lbl_wifite_status.configure(text="Verificando Wifite e interfaces…", text_color=CYAN)

        def worker() -> None:
            ok, status = WifiteCore.probe()
            interfaces = WifiteCore.list_interfaces()

            def update() -> None:
                self.lbl_wifite_status.configure(
                    text=status, text_color=RADAR_GREEN if ok else DANGER
                )
                self.wifite_iface.configure(values=interfaces)
                if interfaces:
                    self.wifite_iface.set(interfaces[0])

            self._ui_call(update)

        threading.Thread(target=worker, daemon=True).start()

    def _select_wifite_wordlist(self) -> None:
        filename = filedialog.askopenfilename(
            filetypes=[("Diccionarios", "*.txt *.lst"), ("Todos", "*.*")]
        )
        if filename:
            self._wifite_wordlist = Path(filename)
            self.lbl_wifite_wordlist.configure(text=Path(filename).name, text_color=RADAR_GREEN)

    def _wifite_log(self, message: str, level: str = "INFO") -> None:
        color_prefix = {"ERROR": "[ERROR] ", "WARNING": "[AVISO] ", "OK": "[OK] "}.get(level, "")
        self._append_text(self.wifite_console, color_prefix + message + "\n")

    def _start_wifite(self) -> None:
        interface = self.wifite_iface.get().strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", interface):
            messagebox.showwarning(
                "Wifite", "No existe una interfaz wireless operativa. Conecta la Alfa a Kali y pulsa Refrescar.",
                parent=self,
            )
            return
        try:
            scan_time = int(self.wifite_scan_time.get() or "30")
            power = int(self.wifite_power.get() or "45")
            targets = int(self.wifite_targets.get() or "1")
            args = WifiteCore.build_args(
                interface=interface,
                mode=self.wifite_mode.get(),
                scan_time=scan_time,
                min_power=power,
                max_targets=targets,
                bssid=self.wifite_bssid.get().strip(),
                passive=bool(self.wifite_passive.get()),
                kill_conflicts=bool(self.wifite_kill.get()),
                random_mac=bool(self.wifite_random_mac.get()),
                ignore_cracked=bool(self.wifite_ignore_cracked.get()),
                wordlist=self._wifite_wordlist,
            )
        except (TypeError, ValueError) as exc:
            messagebox.showerror("Wifite", str(exc), parent=self)
            return
        active_text = (
            "Modo pasivo: no se enviarán tramas de deautenticación."
            if self.wifite_passive.get()
            else "Modo activo: Wifite puede enviar deautenticaciones al objetivo seleccionado."
        )
        if self.wifite_kill.get():
            active_text += " También puede detener procesos de red en Kali durante la ejecución."
        if not messagebox.askyesno(
            "Iniciar Wifite", active_text + "\n\nLa salida aparecerá únicamente dentro de esta pestaña. ¿Continuar?",
            parent=self,
        ):
            return
        self._stop["wifite"].clear()
        self.wifite_console.delete("1.0", "end")
        self._set_run_buttons(self.btn_wifite_start, self.btn_wifite_stop, True)
        self.lbl_wifite_status.configure(text="Wifite ejecutándose…", text_color=WARNING)

        def worker() -> None:
            code = WifiteCore.run(args, self._stop["wifite"], self._wifite_log)

            def done() -> None:
                self._set_run_buttons(self.btn_wifite_start, self.btn_wifite_stop, False)
                self.lbl_wifite_status.configure(
                    text=f"Finalizado · código {code}",
                    text_color=RADAR_GREEN if code == 0 else WARNING,
                )

            self._ui_call(done)

        threading.Thread(target=worker, daemon=True).start()

    def _show_wifite_cracked(self) -> None:
        if not messagebox.askyesno(
            "Resultados de Wifite",
            "Se mostrarán en pantalla las credenciales recuperadas previamente por Wifite. ¿Continuar?",
            parent=self,
        ):
            return
        self.wifite_console.delete("1.0", "end")
        threading.Thread(
            target=lambda: WifiteCore.cracked(self._wifite_log), daemon=True
        ).start()

    def _install_wifite(self) -> None:
        self.wifite_console.delete("1.0", "end")

        def worker() -> None:
            ok, status = WifiteCore.probe()
            if ok:
                self._wifite_log(status, "OK")
                self._ui_call(lambda: self.lbl_wifite_status.configure(
                    text=status, text_color=RADAR_GREEN
                ))
                return
            self._wifite_log("Wifite no está disponible; iniciando instalación…", "WARNING")
            installed = WifiteCore.install(self._wifite_log)
            self._ui_call(lambda: self.lbl_wifite_status.configure(
                text="Wifite instalado" if installed else "Falló la instalación",
                text_color=RADAR_GREEN if installed else DANGER,
            ))

        threading.Thread(target=worker, daemon=True).start()

    # ── TAB: Nmap ────────────────────────────────────────────
    def _build_tab_nmap(self) -> None:
        tab = self.tabs.tab("Nmap")
        f = ctk.CTkFrame(tab)
        f.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(f, text="CIDR / IP:").grid(row=0, column=0, padx=10, sticky="e")
        self.entry_nmap_t = ctk.CTkEntry(f, width=230, placeholder_text="192.168.1.0/24")
        self.entry_nmap_t.grid(row=0, column=1, padx=10, pady=8, sticky="w")
        ctk.CTkButton(f, text="IP Actual", command=self._fill_local_ip,
                      width=100).grid(row=0, column=2, padx=4)

        ctk.CTkLabel(f, text="Modo:").grid(row=1, column=0, padx=10, sticky="e")
        self.nmap_mode = ctk.CTkComboBox(
            f, values=["Host Discovery (-sn)", "Service Scan (-sV -sC)", "OS Detection (-O)"],
            width=260)
        self.nmap_mode.grid(row=1, column=1, padx=10, pady=8, sticky="w")

        bf = ctk.CTkFrame(f, fg_color="transparent")
        bf.grid(row=2, column=0, columnspan=3, pady=12)
        self.btn_nmap = ctk.CTkButton(
            bf, text="Iniciar nmap", command=self._start_nmap, fg_color="#005b96",
        )
        self.btn_nmap.pack(side="left", padx=8)
        self.btn_nmap_stop = ctk.CTkButton(
            bf, text="Detener",
            command=lambda: self._request_stop("nmap", self.btn_nmap_stop),
            fg_color=BUTTON_IDLE, state="disabled", width=100,
        )
        self.btn_nmap_stop.pack(side="left", padx=8)

        self.nmap_console = ctk.CTkTextbox(tab, font=("Courier New", 11), text_color="#a5d6ff")
        self.nmap_console.pack(expand=True, fill="both", padx=20, pady=(0, 10))

    def _fill_local_ip(self) -> None:
        self._log("Consultando IP local en segundo plano…", "INFO")

        def worker() -> None:
            ip = ReconCore.get_local_ip()
            if ip != "N/A":
                cidr = ip.rsplit(".", 1)[0] + ".0/24"

                def update() -> None:
                    self.entry_nmap_t.delete(0, "end")
                    self.entry_nmap_t.insert(0, cidr)

                self._ui_call(update)
                self._log("IP local: " + ip + " -> CIDR: " + cidr, "OK")
            else:
                self._log("Sin IP Wi-Fi activa detectada.", "WARNING")

        threading.Thread(target=worker, daemon=True).start()

    def _start_nmap(self) -> None:
        target = clamp_str(self.entry_nmap_t.get().strip(), MAX_IP_LENGTH)
        if not target:
            return
        self._stop["nmap"].clear()
        self._set_run_buttons(
            self.btn_nmap, self.btn_nmap_stop, True,
            start_color="#005b96", stop_color=BUTTON_STOP,
        )
        self.nmap_console.delete("1.0", "end")
        mode = self.nmap_mode.get()

        def _log(msg: str, lvl: str = "INFO") -> None:
            self._append_text(self.nmap_console, msg + "\n")

        def _worker() -> None:
            if "Host Discovery" in mode:
                hosts = NmapCore.host_discovery(target, _log, self._stop["nmap"])
                _log("\n[+] " + str(len(hosts)) + " hosts activos.", "OK")
                for h in hosts:
                    _log("  " + h["ip"] + "  " + h["hostname"], "OK")
            else:
                ip_clean = re.sub(r"/\d+$", "", target)
                NmapCore.service_scan(ip_clean, _log, self._stop["nmap"])
            self._ui_call(lambda: self._set_run_buttons(
                self.btn_nmap, self.btn_nmap_stop, False, start_color="#005b96"
            ))
            self._log("Nmap finalizado.", "OK")

        threading.Thread(target=_worker, daemon=True).start()

    # ── TAB: Calidad / rendimiento ───────────────────────────
    def _build_tab_quality(self) -> None:
        tab = self.tabs.tab("Calidad")
        top = ctk.CTkFrame(tab, fg_color=PANEL_BG)
        top.pack(fill="x", padx=16, pady=12)
        ctk.CTkLabel(top, text="Host de referencia:").pack(side="left", padx=(12, 4), pady=10)
        self.quality_host = ctk.CTkEntry(top, width=160)
        self.quality_host.insert(0, "8.8.8.8")
        self.quality_host.pack(side="left", padx=4)
        ctk.CTkButton(top, text="▶ Prueba rápida", command=lambda: self._start_quality(False),
                      fg_color="#238636", width=145).pack(side="left", padx=12)
        ctk.CTkButton(top, text="Prueba completa + Speedtest", command=lambda: self._start_quality(True),
                      fg_color="#155f75", width=210).pack(side="left", padx=4)
        self.lbl_quality_status = ctk.CTkLabel(top, text="LISTO", text_color=WARNING,
                                               font=("Consolas", 11, "bold"))
        self.lbl_quality_status.pack(side="right", padx=14)

        cards = ctk.CTkFrame(tab, fg_color="transparent")
        cards.pack(fill="x", padx=16, pady=8)
        self.quality_labels: Dict[str, ctk.CTkLabel] = {}
        definitions = [
            ("ping", "PING", "-- ms", CYAN), ("jitter", "JITTER", "-- ms", RADAR_GREEN),
            ("loss", "PÉRDIDA", "-- %", DANGER), ("http", "HTTP", "-- Mbps", WARNING),
            ("download", "DESCARGA", "-- Mbps", RADAR_GREEN), ("upload", "SUBIDA", "-- Mbps", CYAN),
        ]
        for idx, (key, title, initial, color) in enumerate(definitions):
            card = ctk.CTkFrame(cards, fg_color=PANEL_BG, border_width=1, border_color="#203b2b")
            card.grid(row=0, column=idx, padx=5, sticky="ew")
            cards.grid_columnconfigure(idx, weight=1)
            ctk.CTkLabel(card, text=title, text_color="#7fa58a", font=("Consolas", 10, "bold")).pack(pady=(14, 2))
            label = ctk.CTkLabel(card, text=initial, text_color=color, font=("Segoe UI", 20, "bold"))
            label.pack(pady=(2, 14))
            self.quality_labels[key] = label

        details = ctk.CTkFrame(tab, fg_color=PANEL_BG)
        details.pack(expand=True, fill="both", padx=16, pady=(8, 14))
        ctk.CTkLabel(details, text="CONSOLA DE CALIDAD", text_color=CYAN,
                     font=("Consolas", 12, "bold")).pack(anchor="w", padx=12, pady=8)
        self.quality_console = ctk.CTkTextbox(details, font=("Consolas", 11), fg_color="#050b08")
        self.quality_console.pack(expand=True, fill="both", padx=10, pady=(0, 10))
        self.quality_results: Dict[str, float] = {}

    def _start_quality(self, complete: bool) -> None:
        host = self.quality_host.get().strip() or "8.8.8.8"
        if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", host):
            messagebox.showerror("Host", "Host de referencia no válido.")
            return
        self.lbl_quality_status.configure(text="EJECUTANDO…", text_color=CYAN)
        self.quality_console.delete("1.0", "end")
        threading.Thread(target=self._quality_worker, args=(host, complete), daemon=True).start()

    def _quality_worker(self, host: str, complete: bool) -> None:
        def qlog(text_value: str) -> None:
            self._ui_call(lambda value=text_value: (
                self.quality_console.insert("end", value + "\n"), self.quality_console.see("end")
            ))
        qlog(f"[1/3] ICMP a {host}")
        icmp = QualityCore.ping(host)
        qlog(f"      ping={icmp['ping']:.1f} ms · jitter={icmp['jitter']:.1f} ms · pérdida={icmp['loss']:.1f}%")
        qlog("[2/3] Throughput HTTPS sostenido")
        http_mbps = QualityCore.http_throughput()
        qlog(f"      {http_mbps:.1f} Mbps")
        download = upload = 0.0
        if complete:
            qlog("[3/3] Capacidad máxima mediante Speedtest")
            try:
                download, upload = QualityCore.speedtest()
                qlog(f"      descarga={download:.1f} Mbps · subida={upload:.1f} Mbps")
            except Exception as exc:
                qlog(f"      Speedtest no disponible: {exc}")
        else:
            qlog("[3/3] Speedtest omitido en prueba rápida")
        results = {**icmp, "http": http_mbps, "download": download, "upload": upload}
        self.quality_results = results

        def update() -> None:
            units = {"ping": "ms", "jitter": "ms", "loss": "%", "http": "Mbps", "download": "Mbps", "upload": "Mbps"}
            for key, label in self.quality_labels.items():
                label.configure(text=f"{results[key]:.1f} {units[key]}")
            self.lbl_quality_status.configure(text="FINALIZADO", text_color=RADAR_GREEN)
        self._ui_call(update)
        self._log("Prueba de calidad finalizada.", "OK")

    # ── TAB: Herramientas ────────────────────────────────────
    def _build_tab_tools(self) -> None:
        tab = self.tabs.tab("Herramientas")
        top = ctk.CTkFrame(tab)
        top.pack(fill="x", padx=10, pady=8)
        ctk.CTkButton(top, text="Verificar Todas",
                      command=lambda: threading.Thread(
                          target=self._check_tools, daemon=True).start(),
                      width=170).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Instalar Chocolatey",
                      command=self._install_choco,
                      fg_color="#6e4c2f", width=200).pack(side="left", padx=8)

        cols_t = ("Herramienta", "Estado", "Ruta / Info", "Chocolatey", "URL")
        self.tree_tools = ttk.Treeview(tab, columns=cols_t, show="headings", height=6)
        wt = {"Herramienta": 120, "Estado": 110, "Ruta / Info": 340,
              "Chocolatey": 110, "URL": 280}
        for c in cols_t:
            self.tree_tools.heading(c, text=c)
            self.tree_tools.column(c, width=wt.get(c, 100), anchor="w")
        vsb_t = ttk.Scrollbar(tab, orient="vertical", command=self.tree_tools.yview)
        hsb_t = ttk.Scrollbar(tab, orient="horizontal", command=self.tree_tools.xview)
        self.tree_tools.configure(yscrollcommand=vsb_t.set, xscrollcommand=hsb_t.set)
        self.tree_tools.pack(expand=False, fill="both", padx=10, pady=4)
        hsb_t.pack(fill="x", padx=10)

        ctk.CTkButton(tab, text="Instalar herramienta seleccionada (choco)",
                      command=self._install_selected,
                      fg_color="#4b3619").pack(pady=6)

        self.tools_console = ctk.CTkTextbox(tab, height=140,
                                             font=("Courier New", 11), text_color="#d2a849")
        self.tools_console.pack(expand=True, fill="both", padx=10, pady=(0, 8))

        for name, cfg in TOOLS_CONFIG.items():
            self.tree_tools.insert("", "end", iid=name,
                values=(name, "Sin verificar", cfg["desc"],
                        cfg.get("choco") or "Manual", cfg.get("url", "")),
                tags=("pending",))
        self.tree_tools.tag_configure("pending", foreground="#8b949e")
        self.tree_tools.tag_configure("found",   foreground="#3fb950")
        self.tree_tools.tag_configure("missing", foreground="#f85149")

    def _check_tools(self) -> None:
        self._ui_call(lambda: self.tools_console.delete("1.0", "end"))
        self._ui_call(lambda: self.tools_console.insert(
            "end", "Buscando herramientas en PATH y rutas estandar Windows...\n\n"))
        results = DependencyManager.check_all()
        self._ui_call(lambda: self._update_tools(results))

    def _update_tools(self, results: Dict[str, Tuple[bool, str]]) -> None:
        for name, (found, path_info) in results.items():
            tag    = "found" if found else "missing"
            status = "INSTALADO" if found else "NO ENCONTRADO"
            cur = list(self.tree_tools.item(name, "values"))
            cur[1] = status
            cur[2] = path_info
            self.tree_tools.item(name, values=cur, tags=(tag,))
            icon = "OK" if found else "FALTA"
            self.tools_console.insert(
                "end", "  [" + icon + "] " + name + "\n"
                "         -> " + path_info + "\n")
        self.tools_console.insert("end", "\nVerificacion completada.\n")

    def _install_selected(self) -> None:
        sel = self.tree_tools.selection()
        if not sel:
            return
        name = sel[0]
        pkg  = TOOLS_CONFIG.get(name, {}).get("choco")
        if not pkg:
            url = TOOLS_CONFIG.get(name, {}).get("url", "")
            messagebox.showinfo("Instalacion manual",
                                name + " requiere instalacion manual.\n" + url)
            return
        self.tools_console.insert("end", "\n[*] Instalando " + name + " via choco...\n")
        threading.Thread(target=self._install_pkg,
                         args=(name, pkg), daemon=True).start()

    def _install_pkg(self, name: str, pkg: str) -> None:
        ok, out = DependencyManager.install_via_choco(pkg)
        msg = ("OK " if ok else "ERROR ") + name
        self._ui_call(lambda: self.tools_console.insert("end", out + "\n" + msg + "\n"))
        self._log(msg, "OK" if ok else "ERROR")

    def _install_choco(self) -> None:
        ok, path = DependencyManager.check_choco()
        if ok:
            messagebox.showinfo("Chocolatey", "Ya esta instalado en: " + path)
            return
        self.tools_console.insert(
            "end", "[*] Instalando Chocolatey (requiere admin PowerShell)...\n")
        threading.Thread(target=self._choco_worker, daemon=True).start()

    def _choco_worker(self) -> None:
        ok, out = DependencyManager.install_choco()
        msg = "Chocolatey instalado" if ok else "Error — ejecutar como Administrador"
        self._ui_call(lambda: self.tools_console.insert("end", out + "\n" + msg + "\n"))
        self._log(msg, "OK" if ok else "ERROR")

    # ── Reporte ──────────────────────────────────────────────
    def _export_report(self) -> None:
        prefix = clamp_str(
            self.prefix_entry.get().strip() or REPORT_DEFAULT_NAME, MAX_PREFIX_LENGTH)

        def worker() -> None:
            try:
                out = ReportGenerator.generate(
                    self.scan_results, self.adapter_info, prefix,
                    getattr(self, "quality_results", None), self.capabilities,
                )
                self._log("Reporte generado sin abrir ventanas: " + str(out), "OK")
            except Exception as exc:
                self._log("Error reporte: " + str(exc), "ERROR")

        threading.Thread(target=worker, daemon=True).start()

    # ── Thread-safe UI dispatcher ────────────────────────────
    def _ui_call(self, callback: Any) -> None:
        if threading.get_ident() == self._main_thread_id:
            callback()
        else:
            self._ui_tasks.put(callback)

    def _append_text(self, widget: Any, text_value: str) -> None:
        def write() -> None:
            widget.insert("end", text_value)
            widget.see("end")
        self._ui_call(write)

    def _drain_ui_tasks(self) -> None:
        try:
            for _ in range(200):
                try:
                    callback = self._ui_tasks.get_nowait()
                except queue.Empty:
                    break
                try:
                    callback()
                except Exception as exc:
                    if hasattr(self, "console"):
                        self.console.insert("end", f"[UI][ERROR] {exc}\n")
        finally:
            if self.winfo_exists():
                self.after(80, self._drain_ui_tasks)

    def _on_close(self) -> None:
        self._radar_stop.set()
        self._wardrive_stop.set()
        for event in self._stop.values():
            event.set()
        try:
            current_clipboard = self.clipboard_get()
            if current_clipboard in self._credential_passwords.values():
                self.clipboard_clear()
        except Exception:
            pass
        self._credential_passwords.clear()
        if hasattr(self, "gps_manager"):
            self.gps_manager.stop()
        if self._wardrive_session_id is not None:
            try:
                self.wardrive_store.end_session(self._wardrive_session_id)
            except Exception:
                pass
        self.destroy()

    # ── Logger ───────────────────────────────────────────────
    def _log(self, message: str, level: str = "INFO") -> None:
        if threading.get_ident() != self._main_thread_id:
            self._ui_tasks.put(lambda m=message, lvl=level: self._log(m, lvl))
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", "[" + ts + "][" + level + "] " + message + "\n")
        self.console.see("end")


def run_self_test() -> None:
    fixture = """
SSID 1 : Oficina
    Tipo de red : Infraestructura
    Autenticación : WPA2-Personal
    Cifrado : CCMP
    BSSID 1 : AA:BB:CC:11:22:33
         Señal : 82%
         Tipo de radio : 802.11ac
         Canal : 44
SSID 2 :
    Tipo de red : Infraestructura
    Autenticación : Abierta
    Cifrado : Ninguno
    BSSID 1 : 00:11:22:33:44:55
         Señal : 36%
         Tipo de radio : 802.11n
         Canal : 6
"""
    parsed = ReconCore._parse(fixture)
    assert len(parsed) == 2
    assert parsed[0].ssid == "Oficina" and parsed[0].channel == "44"
    assert parsed[0].score >= 70 and parsed[1].score == 0
    assert proximity_label("82%") == "MUY CERCA"
    assert signal_dbm("82%") == -59

    iw_fixture = """BSS aa:bb:cc:11:22:33(on wlan0)
\tfreq: 5180
\tsignal: -41.00 dBm
\tcapability: ESS Privacy
\tSSID: Alfa-Lab
\tVHT capabilities:
\tRSN:
\t\t* Pairwise ciphers: CCMP
\t\t* Authentication suites: PSK
"""
    alfa_parsed = AlfaWslCore._parse_iw_scan(iw_fixture)
    assert len(alfa_parsed) == 1 and alfa_parsed[0].channel == "36"
    assert alfa_parsed[0].auth == "WPA2-Personal" and parse_signal_percent(alfa_parsed[0].signal) == 100
    assert alfa_parsed[0].cipher == "CCMP" and alfa_parsed[0].score_label == "WPA2/AES"

    # El modo automático debe seguir siendo plenamente utilizable en un Windows
    # sin WSL/Kali: no exige el puente y vuelve al inventario nativo de netsh.
    fallback_fixture = NetworkEntry(
        ssid="WINDOWS-LAB", bssid="10:20:30:40:50:60", signal="72%",
        channel="6", auth="WPA2-Personal", cipher="CCMP",
    )
    original_ensure = AlfaWslCore.ensure_ready
    original_alfa_scan = AlfaWslCore.scan_networks
    original_alfa_status = AlfaWslCore.status
    original_windows_scan = ReconCore.scan
    original_get_alfa = AdapterManager.get_alfa_info
    original_get_alfa_interface = AdapterManager.get_alfa_interface_name
    original_get_info = AdapterManager.get_info
    try:
        AlfaWslCore.ensure_ready = staticmethod(lambda _log_cb: False)
        AlfaWslCore.scan_networks = staticmethod(lambda: [])
        AlfaWslCore.status = staticmethod(lambda: "Shared")
        AdapterManager.get_alfa_info = staticmethod(lambda: AdapterInfo())
        AdapterManager.get_alfa_interface_name = staticmethod(lambda: "")
        AdapterManager.get_info = staticmethod(lambda: AdapterInfo(name="Wi-Fi"))
        ReconCore.scan = staticmethod(lambda interface="": [fallback_fixture])
        fallback_results, fallback_engine = AuditorGUI._scan_with_source("Automático (Alfa preferida)")
        assert fallback_results == [fallback_fixture]
        assert fallback_engine == "WINDOWS · WI-FI INTEGRADA"

        selected_interfaces: List[str] = []
        AdapterManager.get_alfa_interface_name = staticmethod(lambda: "Wi-Fi 2")
        ReconCore.scan = staticmethod(
            lambda interface="": selected_interfaces.append(interface) or [fallback_fixture]
        )
        alfa_results, alfa_engine = AuditorGUI._scan_with_source("Automático (Alfa preferida)")
        assert alfa_results == [fallback_fixture] and selected_interfaces == ["Wi-Fi 2"]
        assert alfa_engine == "ALFA · WINDOWS · Wi-Fi 2"
    finally:
        AlfaWslCore.ensure_ready = staticmethod(original_ensure)
        AlfaWslCore.scan_networks = staticmethod(original_alfa_scan)
        AlfaWslCore.status = staticmethod(original_alfa_status)
        ReconCore.scan = staticmethod(original_windows_scan)
        AdapterManager.get_alfa_info = staticmethod(original_get_alfa)
        AdapterManager.get_alfa_interface_name = staticmethod(original_get_alfa_interface)
        AdapterManager.get_info = staticmethod(original_get_info)

    fix = GPSManager.parse_nmea("$GPGGA,123519,1438.0940,N,09030.4140,W,1,08,0.9,1495.4,M,46.9,M,,*47")
    assert fix and fix.valid and abs(float(fix.latitude) - 14.6349) < 0.001
    assert abs(float(fix.longitude) + 90.5069) < 0.001
    moving = GPSManager.parse_nmea(
        "$GPRMC,123520,A,1438.0940,N,09030.4140,W,10.0,82.4,020926,,,A*68"
    )
    assert moving and moving.valid and abs(float(moving.speed_kmh or 0) - 18.52) < 0.01
    assert abs(float(moving.heading or 0) - 82.4) < 0.01

    with tempfile.TemporaryDirectory(prefix="wireless_audit_selftest_") as temp_dir:
        store = WardriveStore(Path(temp_dir) / "test.sqlite3")
        session = store.begin_session("SELFTEST", "TEST")
        store.add_observation(session, parsed[0], fix, "TEST")
        store.end_session(session)
        networks, observations = store.counts(session)
        assert networks == 1 and observations == 1
        features = WardriveExporter._features(store.best_networks(session))
        assert len(features) == 1 and features[0]["properties"]["ssid"] == "Oficina"

    profile = AttackCore._build_profile("SSID & Test", "Abc<12345&", "WPA2-Personal")
    assert "SSID &amp; Test" in profile and "Abc&lt;12345&amp;" in profile

    saved_fixture = """
Perfiles de usuario
-------------------
    Perfil de todos los usuarios     : Oficina Segura
    All User Profile                 : Lab-WiFi
"""
    assert WifiCredentialCore._parse_windows_profile_names(saved_fixture) == ["Oficina Segura", "Lab-WiFi"]
    assert WifiCredentialCore._value_for_labels(
        "    Contenido de la clave : S3cret-Test", WifiCredentialCore.WINDOWS_KEY_LABELS
    ) == "S3cret-Test"
    assert WifiCredentialCore.classify("Abierta", "") == ("Red abierta", False)
    assert WifiCredentialCore.classify("WPA2-Enterprise", "") == ("Credenciales 802.1X", False)
    assert WifiCredentialCore.classify(
        "WPA2-Personal", "    Clave de seguridad : Presente"
    ) == ("PSK guardada", True)
    assert WifiCredentialCore.classify(
        "WPA2-Personal", "    Security key : Absent"
    ) == ("PSK no guardada", False)

    usbipd_fixture = """Connected:
BUSID  VID:PID    DEVICE                  STATE
2-10   8087:0026  Intel Bluetooth         Not shared

Persisted:
GUID                                  DEVICE
12345678-1234-1234-1234-123456789abc  Realtek 8814AU Wireless LAN 802.11ac USB NIC
"""
    connected_usb, persisted_usb = CapabilityEngine._usbipd_sections(usbipd_fixture)
    assert "8814AU" not in connected_usb and "8814AU" in persisted_usb
    connected_usb, persisted_usb = CapabilityEngine._usbipd_sections(
        usbipd_fixture.replace("2-10   8087:0026  Intel Bluetooth", "2-4    0bda:8813  Realtek 8814AU")
    )
    assert "0bda:8813" in connected_usb and "8814AU" in persisted_usb

    wifite_args = WifiteCore.build_args(
        "wlan0", "WPA/WPA2", 30, 45, 1, bssid="AA:BB:CC:DD:EE:FF",
        passive=True, ignore_cracked=True,
    )
    assert wifite_args[:3] == ["wifite", "-i", "wlan0"]
    assert "--nodeauths" in wifite_args and "--wpa" in wifite_args
    assert strip_ansi("\x1b[32mOK\x1b[0m") == "OK"
    print("WIRELESS_AUDIT_PRO_SELFTEST_OK")


def run_gui_smoke() -> None:
    app = AuditorGUI()
    original_scan = ReconCore.scan
    try:
        app.update_idletasks()
        assert app.state() == "withdrawn"
        button_pairs = (
            (app.btn_radar_start, app.btn_radar_stop, BUTTON_START),
            (app.btn_wardrive_start, app.btn_wardrive_stop, BUTTON_START),
            (app.btn_wifite_start, app.btn_wifite_stop, BUTTON_START),
        )
        assert app.btn_validate_alfa.cget("state") == "normal"
        for start_button, stop_button, start_color in button_pairs:
            assert start_button.cget("state") == "normal"
            assert stop_button.cget("state") == "disabled"
            app._set_run_buttons(start_button, stop_button, True, start_color=start_color)
            assert start_button.cget("state") == "disabled" and start_button.cget("fg_color") == BUTTON_IDLE
            assert stop_button.cget("state") == "normal"
            app._set_run_buttons(start_button, stop_button, False, start_color=start_color)
            assert stop_button.cget("state") == "disabled" and stop_button.cget("fg_color") == BUTTON_IDLE
        app._set_run_buttons(app.btn_radar_start, app.btn_radar_stop, True)
        assert app.btn_radar_start.cget("state") == "disabled"
        assert app.btn_radar_start.cget("fg_color") == BUTTON_IDLE
        assert app.btn_radar_stop.cget("state") == "normal"
        app._set_run_buttons(app.btn_radar_start, app.btn_radar_stop, False)
        sample = NetworkEntry(
            ssid="LAB", bssid="AA:BB:CC:DD:EE:FF", signal="82%",
            channel="6", auth="WPA2-Personal", cipher="CCMP",
        )
        app._update_radar([sample])
        assert app.spectrum_canvas.networks and app.spectrum_metrics["2.4 GHz"].cget("text") == "1"
        ReconCore.scan = staticmethod(lambda interface="": [sample])
        app.scan_source_combo.set("Wi-Fi integrada Windows")
        app._start_radar()
        assert app.btn_radar_start.cget("state") == "disabled"
        assert app.btn_radar_start.cget("fg_color") == BUTTON_IDLE
        assert app.btn_radar_stop.cget("state") == "normal" and app.radar_canvas._running
        app._stop_radar()
        assert app.btn_radar_stop.cget("state") == "disabled" and not app.radar_canvas._running
        app._radar_thread.join(timeout=2)
        app._drain_ui_tasks()
        assert app.btn_radar_start.cget("state") == "normal"

        credential_samples = [
            SavedWifiProfile("PERSONAL", "WPA2-Personal", "PSK guardada", True),
            SavedWifiProfile("ABIERTA", "Abierta", "Red abierta", False),
            SavedWifiProfile("EMPRESA", "WPA2-Enterprise", "Credenciales 802.1X", False),
        ]
        app._update_credentials(credential_samples)
        credential_values = {
            app._credential_iid_to_profile[iid]: app.tree_credentials.item(iid, "values")
            for iid in app.tree_credentials.get_children()
        }
        assert credential_values["PERSONAL"][2] == "••••••••"
        assert credential_values["ABIERTA"][2] == "No aplica"
        assert credential_values["EMPRESA"][2] == "No aplica"
        app._hide_credentials()
        assert app.tree_credentials.item(
            next(iid for iid, name in app._credential_iid_to_profile.items() if name == "ABIERTA"),
            "values",
        )[2] == "No aplica"

        map_networks = [
            NetworkEntry(
                ssid=f"MAP-{index:03d}",
                bssid=f"02:00:00:{index // 256:02X}:{index % 256:02X}:01",
                signal=f"{40 + index % 60}%", channel=str(1 + index % 11),
                auth="WPA2-Personal", cipher="CCMP", score=78,
            )
            for index in range(240)
        ]
        map_fix = GPSFix(latitude=14.6349, longitude=-90.5069, source="SMOKE")
        map_started = time.monotonic()
        for _ in range(8):
            app._update_map_markers(map_networks, map_fix)
        for step in range(25):
            app._update_map_route((14.6349 + step * 0.00004, -90.5069))
        assert len(app._wardrive_markers) == MAP_MAX_MARKERS
        assert len(app._wardrive_map_track) == 25
        assert app._wardrive_path is not None
        assert len(app._wardrive_path.position_list) == len(app._wardrive_map_track)
        assert time.monotonic() - map_started < 3.0
        print("WIRELESS_AUDIT_PRO_GUI_SMOKE_OK")
    finally:
        ReconCore.scan = staticmethod(original_scan)
        app.destroy()


def print_diagnostics() -> None:
    adapter = AdapterManager.get_info()
    capabilities = CapabilityEngine.probe(adapter.name)
    payload = {
        "version": VERSION,
        "adapter": asdict(adapter),
        "capabilities": asdict(capabilities),
        "tools": DependencyManager.check_all(),
        "gps_sources": GPSManager.sources(),
        "map_widget": MAP_WIDGET_AVAILABLE,
        "wifite": WifiteCore.probe(),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


# =========================================================
# === ENTRY POINT ===
# =========================================================
if __name__ == "__main__":
    if "--self-test" in sys.argv:
        run_self_test()
    elif "--gui-smoke" in sys.argv:
        run_gui_smoke()
    elif "--diagnose" in sys.argv:
        print_diagnostics()
    else:
        app = AuditorGUI()
        if "--open-credentials" in sys.argv:
            app.tabs.set("Claves Wi-Fi")
            app.after(250, app._refresh_credentials)
        app.mainloop()
