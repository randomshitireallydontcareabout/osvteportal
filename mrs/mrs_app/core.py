


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MRS Ticket Dashboard - single-file app.
"""

import os, sys, importlib, json

BOOTSTRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_PACKAGE_PREFIX = ".mrs_packages_py{}{}".format(
    sys.version_info.major, sys.version_info.minor
)
REQUIRED_IMPORTS = (
    "flask",
    "werkzeug",
    "markupsafe",
    "jinja2",
    "cryptography",
    "fpdf",
)


def _missing_imports():
    """Return required modules that are unavailable on the active Python path."""
    importlib.invalidate_caches()
    return [name for name in REQUIRED_IMPORTS if importlib.util.find_spec(name) is None]


def _find_valid_local_packages():
    """Reuse an existing project-local package folder without installing anything."""
    try:
        names = sorted(os.listdir(BOOTSTRAP_DIR), reverse=True)
    except OSError:
        return None

    for name in names:
        if not name.startswith(LOCAL_PACKAGE_PREFIX):
            continue

        candidate = os.path.join(BOOTSTRAP_DIR, name)
        if not os.path.isdir(candidate):
            continue

        sys.path.insert(0, candidate)
        try:
            if not _missing_imports():
                return candidate
        finally:
            if sys.path and sys.path[0] == candidate:
                sys.path.pop(0)

    return None


def ensure_packages():
    """
    Use packages already installed in the active virtual environment.
    If they are unavailable there, reuse a valid existing project-local package
    directory. This function never runs pip and never downloads packages.
    """
    missing = _missing_imports()
    if not missing:
        print("Required packages are already installed. Skipping installation.")
        return

    package_dir = _find_valid_local_packages()
    if package_dir:
        if package_dir in sys.path:
            sys.path.remove(package_dir)
        sys.path.insert(0, package_dir)
        importlib.invalidate_caches()
        print("Using existing project-local packages:", package_dir)
        return

    pip_names = {
        "flask": "flask",
        "werkzeug": "werkzeug",
        "markupsafe": "markupsafe",
        "jinja2": "jinja2",
        "cryptography": "cryptography",
        "fpdf": "fpdf2",
    }
    install_names = [pip_names.get(name, name) for name in missing]
    print("Missing required packages:", ", ".join(install_names))
    print("Automatic package installation is disabled.")
    print(
        "Install them once in the active virtual environment with:\n  "
        + sys.executable
        + " -m pip install "
        + " ".join(install_names)
    )
    raise SystemExit(1)


ensure_packages()

import os, re, csv, ssl, math, socket, sqlite3, secrets, datetime, base64, json
import urllib.parse, urllib.request, urllib.error, hmac, hashlib, threading, webbrowser, io
import tempfile
from io import StringIO, BytesIO
from functools import wraps
from flask import (Flask, g, render_template, request, redirect, url_for, session,
                   flash, abort, Response, jsonify, send_file)
from .activity_audit import create_session_log, audit_event, close_session_log
from werkzeug.security import generate_password_hash, check_password_hash
from jinja2 import DictLoader
from werkzeug.serving import make_server
from markupsafe import Markup
from fpdf import FPDF

try:
    import tkinter as tk
    from tkinter import messagebox
    HAS_TK = True
except Exception:
    HAS_TK = False


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
CERT_DIR = os.path.join(BASE_DIR, "certs")


def _database_ticket_count(path):
    if not os.path.isfile(path):
        return -1
    try:
        probe = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
        try:
            tables = {row[0] for row in probe.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            if "tickets" not in tables or "users" not in tables:
                return -1
            return int(probe.execute("SELECT COUNT(*) FROM tickets").fetchone()[0])
        finally:
            probe.close()
    except (sqlite3.Error, OSError, ValueError):
        return -1


def resolve_db_path():
    configured = (os.environ.get("MRS_DB_PATH") or "").strip()
    if configured:
        configured = os.path.abspath(os.path.expanduser(configured))
        if _database_ticket_count(configured) >= 0:
            return configured
        raise RuntimeError(f"MRS_DB_PATH is not a valid MRS database: {configured}")
    search_roots = [BASE_DIR, os.path.dirname(BASE_DIR)]
    candidates = set()
    for root in search_roots:
        if not os.path.isdir(root):
            continue
        for current_root, dirs, files in os.walk(root):
            relative = os.path.relpath(current_root, root)
            depth = 0 if relative == "." else relative.count(os.sep) + 1
            if depth >= 3:
                dirs[:] = []
            if "mrs.db" in files:
                candidates.add(os.path.join(current_root, "mrs.db"))
    ranked = []
    for candidate in candidates:
        count = _database_ticket_count(candidate)
        if count >= 0:
            ranked.append((count, os.path.getsize(candidate), candidate))
    if ranked:
        return max(ranked, key=lambda item: (item[0], item[1]))[2]
    return os.path.join(DATA_DIR, "mrs.db")


DB_PATH = resolve_db_path()
print(f"MRS database: {DB_PATH} ({_database_ticket_count(DB_PATH):,} tickets)")
SECRET_PATH = os.path.join(DATA_DIR, ".secret_key")
YUBICO_CONFIG_PATH = os.path.join(DATA_DIR, "yubico_otp_config.json")

HTTP_PORT = 8080
HTTPS_PORT = 443
BIND_HOST = "0.0.0.0"

YUBICO_CLIENT_ID = (os.environ.get("YUBICO_CLIENT_ID") or "").strip()
YUBICO_SECRET_KEY = (os.environ.get("YUBICO_SECRET_KEY") or "").strip()
YUBICO_VERIFY_URL = "https://api.yubico.com/wsapi/2.0/verify"
YUBIKEY_OTP_PATTERN = re.compile(r"^[cbdefghijklnrtuv]{44}$")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CERT_DIR, exist_ok=True)

if os.path.exists(SECRET_PATH):
    with open(SECRET_PATH, "r", encoding="utf-8") as fh:
        SECRET = fh.read().strip()
else:
    SECRET = secrets.token_hex(32)
    with open(SECRET_PATH, "w", encoding="utf-8") as fh:
        fh.write(SECRET)


app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


@app.before_request
def bypass_auth_for_testing():
    if not session.get("user_id"):
        session["user_id"] = 1
        session["username"] = "admin"
        session["is_admin"] = True
        session["active_section"] = "osv"
        session["requested_section"] = "osv"
    if session.get("user_id") and not session.get("audit_log_path"):
        public_id = None
        try:
            row = get_db().execute("SELECT public_id,device_name FROM yubikey_otp_credentials WHERE user_id=? ORDER BY id LIMIT 1", (session["user_id"],)).fetchone()
            public_id = row["public_id"] if row else None
        except Exception:
            pass
        create_session_log(DATA_DIR, session, user_id=session["user_id"], username=session.get("username","user"), is_admin=bool(session.get("is_admin")), yubikey_public_id=public_id, yubikey_name=(row["device_name"] if row else None), yubikey_holder_name=session.get("username"), ip_address=request.remote_addr or "", user_agent=request.headers.get("User-Agent", ""))
        audit_event(session, "LOGIN_SUCCESS", method=request.method, path=request.path, endpoint=request.endpoint or "", ip_address=request.remote_addr or "")


print("YubiKey OTP validation: environment credentials detected"
      if YUBICO_CLIENT_ID and YUBICO_SECRET_KEY
      else "YubiKey OTP validation: configure in Manage Users")


def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()


def open_firewall_rule(port):
    if os.name != "nt":
        return False, "Only supported on Windows."
    try:
        import ctypes
        rule_name = f"MRS Dashboard (TCP {port})"
        cmd = (f'netsh advfirewall firewall add rule '
               f'name="{rule_name}" dir=in action=allow protocol=TCP localport={port}')
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f'/c {cmd}', None, 1)
        if rc <= 32:
            return False, "Elevation was cancelled or failed."
        return True, "Firewall rule added (or already existed)."
    except Exception as exc:
        return False, str(exc)


def now_standard():
    return datetime.datetime.now().strftime("%Y/%m/%d %I:%M:%S %p")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = """

CREATE TABLE IF NOT EXISTS tester_database (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    brand TEXT NOT NULL,
    memory_type TEXT NOT NULL,
    osv_tester TEXT NOT NULL,
    username TEXT,
    password TEXT,
    mac_address TEXT,
    ip_address TEXT,
    location TEXT,
    remote_access TEXT,
    script_version TEXT,
    all_stockcode TEXT,
    os_version TEXT,
    bios TEXT,
    bmc TEXT,
    work_instruction TEXT,
    last_maintenance_date TEXT,
    images TEXT,
    comments TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS duties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    duty_date TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT,
    duty_type TEXT NOT NULL DEFAULT 'General',
    priority TEXT NOT NULL DEFAULT 'Normal',
    tester_id INTEGER,
    created_by TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tester_id) REFERENCES tester_database(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_duties_date ON duties(duty_date);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stock_code TEXT NOT NULL,
    mrs_ticket TEXT NOT NULL,
    serial_number TEXT,
    mrs_comments TEXT,
    status TEXT NOT NULL DEFAULT 'available',
    assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL,
    technician_name TEXT,
    test_started_at TEXT,
    test_result TEXT,
    failure_reason TEXT,
    wh_location TEXT,
    part_type TEXT,
    part_description TEXT,
    return_time TEXT,
    quality_disposition TEXT,
    logs_uploaded TEXT,
    log_path TEXT,
    stock_cd TEXT,
    bb_flag INTEGER, sxm1_flag INTEGER, sxm2_flag INTEGER, sxm3_flag INTEGER,
    sxm4_flag INTEGER, sxm5_flag INTEGER, sxm6_flag INTEGER, sxm7_flag INTEGER,
    sxm8_flag INTEGER, csv_id INTEGER, csv_index TEXT, modified TEXT,
    transfer_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_assigned ON tickets(assigned_to);
CREATE INDEX IF NOT EXISTS idx_tickets_completed ON tickets(completed_at);
CREATE TABLE IF NOT EXISTS user_permissions (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tab_key TEXT NOT NULL, allowed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, tab_key)
);
CREATE TABLE IF NOT EXISTS section_permissions (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    section_key TEXT NOT NULL CHECK(section_key IN ('osv','te')),
    allowed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, section_key)
);
CREATE TABLE IF NOT EXISTS te_permissions (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tab_key TEXT NOT NULL, allowed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, tab_key)
);
CREATE TABLE IF NOT EXISTS work_instruction_editors (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    allowed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0, device_name TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
CREATE TABLE IF NOT EXISTS yubikey_otp_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_id TEXT NOT NULL UNIQUE, device_name TEXT,
    created_at TEXT NOT NULL, last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_yubiotp_user ON yubikey_otp_credentials(user_id);
"""

DEFAULT_TICKETS = [
    ("STK-1001","MRS-50001","SN-SRV-99881","Standard verification and power check"),
    ("STK-1001","MRS-50002","SN-SRV-99882","Firmware update required"),
    ("STK-1002","MRS-50003","SN-SRV-99883","Check thermal paste and fans"),
    ("STK-2001","MRS-50011","SN-SRV-88111","Memory diagnostic pass"),
    ("STK-2001","MRS-50012","SN-SRV-88112","PCIe lane stress test"),
    ("STK-3001","MRS-50021","SN-SRV-77331","BIOS configuration reset"),
    ("STK-3002","MRS-50022","SN-SRV-77332","Network interface speed verification"),
    ("STK-3003","MRS-50023","SN-SRV-77333","RAID controller array sync"),
    ("STK-4001","MRS-50031","SN-SRV-66551","Power supply unit load test"),
    ("STK-4002","MRS-50032","SN-SRV-66552","High temperature burn-in"),
]


def init_db():
    db = sqlite3.connect(DB_PATH); db.row_factory = sqlite3.Row
    # Ensure all columns exist in tester_database if the table was previously created
    db.executescript("""
        CREATE TABLE IF NOT EXISTS tester_database (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL DEFAULT 'DIMM',
            brand TEXT NOT NULL DEFAULT '',
            memory_type TEXT NOT NULL DEFAULT '',
            osv_tester TEXT NOT NULL DEFAULT '',
            username TEXT,
            password TEXT,
            mac_address TEXT,
            ip_address TEXT,
            location TEXT,
            remote_access TEXT,
            script_version TEXT,
            all_stockcode TEXT,
            os_version TEXT,
            bios TEXT,
            bmc TEXT,
            work_instruction TEXT,
            last_maintenance_date TEXT,
            images TEXT DEFAULT '[]',
            comments TEXT DEFAULT '[]',
            updated_at TEXT
        );
    """)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS duties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            duty_date TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT,
            duty_type TEXT NOT NULL DEFAULT 'General',
            priority TEXT NOT NULL DEFAULT 'Normal',
            tester_id INTEGER,
            created_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tester_id) REFERENCES tester_database(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_duties_date ON duties(duty_date);
    """)
    tester_cols = {r["name"] for r in db.execute("PRAGMA table_info(tester_database)")}
    for col, ctype in [
        ("category", "TEXT NOT NULL DEFAULT 'DIMM'"),
        ("brand", "TEXT NOT NULL DEFAULT ''"),
        ("memory_type", "TEXT NOT NULL DEFAULT ''"),
        ("osv_tester", "TEXT NOT NULL DEFAULT ''"),
        ("username", "TEXT"), ("password", "TEXT"), ("mac_address", "TEXT"),
        ("ip_address", "TEXT"), ("location", "TEXT"), ("remote_access", "TEXT"),
        ("script_version", "TEXT"), ("all_stockcode", "TEXT"), ("os_version", "TEXT"),
        ("bios", "TEXT"), ("bmc", "TEXT"), ("work_instruction", "TEXT"),
        ("last_maintenance_date", "TEXT"), ("images", "TEXT DEFAULT '[]'"),
        ("comments", "TEXT DEFAULT '[]'"), ("updated_at", "TEXT")
    ]:
        if col not in tester_cols:
            db.execute(f"ALTER TABLE tester_database ADD COLUMN {col} {ctype}")

    if db.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0] == 0:
        db.execute("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?,?,1,?)",
                   ("admin", generate_password_hash("admin123"), now_standard()))
    if db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 0:
        db.executemany("INSERT INTO tickets (stock_code,mrs_ticket,serial_number,mrs_comments,created_at) VALUES (?,?,?,?,?)",
                       [(sc, m, s, c, now_standard()) for sc, m, s, c in DEFAULT_TICKETS])
    db.execute("INSERT OR IGNORE INTO section_permissions (user_id, section_key, allowed) SELECT id, 'osv', 1 FROM users")
    db.execute("INSERT OR IGNORE INTO te_permissions (user_id, tab_key, allowed) "
               "SELECT user_id, 'te_pie_tickets', 1 FROM section_permissions WHERE section_key='te' AND allowed=1")
    db.commit(); db.close()


# =========================================================================
# Chart helpers: pie, donut, horizontal bar, vertical bar, stat cards
# =========================================================================
def pie_chart(data, size=220, title=None):
    total = sum(v for _, v, _ in data if v and v > 0)
    cx = cy = size / 2
    r = size / 2 - 5
    if total <= 0:
        svg = (f'<svg viewBox="0 0 {size} {size}" width="100%" style="max-width:{size}px">'
               f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#233458" stroke-width="2"/>'
               f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="middle" fill="#8ea1c2" font-size="11">No data</text></svg>')
    else:
        parts = []; start = -math.pi / 2
        for _, value, color in data:
            if not value or value <= 0: continue
            angle = (value / total) * 2 * math.pi
            end = start + angle
            if value == total:
                parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}" stroke="#0b1220" stroke-width="2"/>')
            else:
                x1 = cx + r * math.cos(start); y1 = cy + r * math.sin(start)
                x2 = cx + r * math.cos(end);   y2 = cy + r * math.sin(end)
                large = 1 if angle > math.pi else 0
                parts.append(f'<path d="M {cx} {cy} L {x1:.2f} {y1:.2f} A {r} {r} 0 {large} 1 {x2:.2f} {y2:.2f} Z" fill="{color}" stroke="#0b1220" stroke-width="2"/>')
            start = end
        svg = (f'<svg viewBox="0 0 {size} {size}" width="100%" style="max-width:{size}px">' + "".join(parts) + "</svg>")
    legend = ('<ul style="list-style:none;padding:0;margin:6px 0 0;font-size:17.5px;width:100%">')
    for label, value, color in data:
        pct = (value / total * 100) if total else 0
        legend += (f'<li style="display:flex;align-items:center;gap:6px;margin:2px 0">'
                   f'<span style="width:8px;height:8px;border-radius:2px;background:{color};flex:0 0 auto"></span>'
                   f'<span style="color:#c6d2e6">{label}</span>'
                   f'<span style="color:#8ea1c2">{value} <span style="opacity:.55">({pct:.0f}%)</span></span></li>')
    legend += "</ul>"
    head = (f'<div style="font-size:10px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:.8px;font-weight:700;margin-bottom:4px">{title}</div>') if title else ""
    return f'<div style="display:flex;flex-direction:column;align-items:center">{head}{svg}{legend}</div>'


def donut_chart(data, size=220, title=None):
    total = sum(v for _, v, _ in data if v and v > 0)
    cx = cy = size / 2
    r_outer = size / 2 - 5
    r_inner = r_outer * 0.55
    r_mid = (r_outer + r_inner) / 2
    stroke_w = r_outer - r_inner
    if total <= 0:
        svg = (f'<svg viewBox="0 0 {size} {size}" width="100%" style="max-width:{size}px">'
               f'<circle cx="{cx}" cy="{cy}" r="{r_mid}" fill="none" stroke="#233458" stroke-width="{stroke_w}"/>'
               f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="middle" fill="#8ea1c2" font-size="11">No data</text></svg>')
    else:
        parts = []; start = -math.pi / 2
        for _, value, color in data:
            if not value or value <= 0: continue
            angle = (value / total) * 2 * math.pi
            end = start + angle
            if value == total:
                parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r_mid}" fill="none" stroke="{color}" stroke-width="{stroke_w}"/>')
            else:
                x1 = cx + r_mid * math.cos(start); y1 = cy + r_mid * math.sin(start)
                x2 = cx + r_mid * math.cos(end);   y2 = cy + r_mid * math.sin(end)
                large = 1 if angle > math.pi else 0
                parts.append(f'<path d="M {x1:.2f} {y1:.2f} A {r_mid} {r_mid} 0 {large} 1 {x2:.2f} {y2:.2f}" fill="none" stroke="{color}" stroke-width="{stroke_w}"/>')
            start = end
        parts.append(f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="middle" fill="#e6ecf7" font-size="{size*0.16:.0f}" font-weight="700">{total}</text>')
        parts.append(f'<text x="{cx}" y="{cy + size*0.12:.0f}" text-anchor="middle" dominant-baseline="middle" fill="#8ea1c2" font-size="{size*0.07:.0f}">Total</text>')
        svg = f'<svg viewBox="0 0 {size} {size}" width="100%" style="max-width:{size}px">' + "".join(parts) + "</svg>"
    legend = ('<ul style="list-style:none;padding:0;margin:6px 0 0;font-size:17.5px;width:100%">')
    for label, value, color in data:
        pct = (value / total * 100) if total else 0
        legend += (f'<li style="display:flex;align-items:center;gap:6px;margin:2px 0">'
                   f'<span style="width:8px;height:8px;border-radius:2px;background:{color};flex:0 0 auto"></span>'
                   f'<span style="color:#c6d2e6">{label}</span>'
                   f'<span style="color:#8ea1c2">{value} <span style="opacity:.55">({pct:.0f}%)</span></span></li>')
    legend += "</ul>"
    head = (f'<div style="font-size:10px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:.8px;font-weight:700;margin-bottom:4px">{title}</div>') if title else ""
    return f'<div style="display:flex;flex-direction:column;align-items:center">{head}{svg}{legend}</div>'


def hbar_chart(data, size=220, title=None):
    n = max(len(data), 1)
    chart_w = max(int(size * 1.7), 340)
    chart_h = n * 44 + 20
    pad_l, pad_r, pad_t = 115, 70, 10
    inner_w = chart_w - pad_l - pad_r
    max_val = max((v for _, v, _ in data if v and v > 0), default=1) or 1
    total = sum(v for _, v, _ in data if v and v > 0) or 1
    bars = []
    for i, (label, value, color) in enumerate(data):
        y = pad_t + i * 44
        w = (value / max_val) * inner_w if max_val else 0
        pct = (value / total * 100) if total else 0
        bars.append(f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="28" fill="{color}" rx="4"/>')
        bars.append(f'<text x="{pad_l-10}" y="{y+19}" text-anchor="end" fill="#c6d2e6" font-size="13" font-weight="600">{label}</text>')
        bars.append(f'<text x="{pad_l+w+10:.1f}" y="{y+19}" fill="#8ea1c2" font-size="12">{value} ({pct:.0f}%)</text>')
    svg = f'<svg viewBox="0 0 {chart_w} {chart_h}" width="100%" style="max-width:{chart_w}px">' + "".join(bars) + "</svg>"
    head = (f'<div style="font-size:10px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:.8px;font-weight:700;margin-bottom:4px">{title}</div>') if title else ""
    return f'<div style="display:flex;flex-direction:column;align-items:center">{head}{svg}</div>'


def vbar_chart(data, size=220, title=None):
    n = max(len(data), 1)
    chart_w = max(size, 220)
    chart_h = int(chart_w * 0.75)
    pad_b, pad_t = 42, 26
    inner_h = chart_h - pad_t - pad_b
    max_val = max((v for _, v, _ in data if v and v > 0), default=1) or 1
    total = sum(v for _, v, _ in data if v and v > 0) or 1
    total_w = chart_w - 16
    slot_w = total_w / n
    bar_w = min(56, slot_w * 0.62)
    bars = []
    for i, (label, value, color) in enumerate(data):
        cx = 8 + slot_w * i + slot_w / 2
        h = (value / max_val) * inner_h if max_val else 0
        y = pad_t + inner_h - h
        x = cx - bar_w / 2
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="{color}" rx="3"/>')
        bars.append(f'<text x="{cx:.1f}" y="{y-6:.1f}" text-anchor="middle" fill="#e6ecf7" font-size="12" font-weight="700">{value}</text>')
        display_label = label if len(label) <= 12 else label[:11] + "…"
        bars.append(f'<text x="{cx:.1f}" y="{chart_h - pad_b + 18}" text-anchor="middle" fill="#8ea1c2" font-size="10">{display_label}</text>')
        pct = (value / total * 100) if total else 0
        bars.append(f'<text x="{cx:.1f}" y="{chart_h - pad_b + 32}" text-anchor="middle" fill="#64748b" font-size="9">{pct:.0f}%</text>')
    svg = f'<svg viewBox="0 0 {chart_w} {chart_h}" width="100%" style="max-width:{chart_w}px">' + "".join(bars) + "</svg>"
    head = (f'<div style="font-size:10px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:.8px;font-weight:700;margin-bottom:4px">{title}</div>') if title else ""
    return f'<div style="display:flex;flex-direction:column;align-items:center">{head}{svg}</div>'


def stat_cards(data, title=None):
    total = sum(v for _, v, _ in data if v and v > 0)
    cards = []
    for label, value, color in data:
        pct = (value / total * 100) if total else 0
        cards.append(
            f'<div style="background:#0d1729;border:1px solid {color};border-radius:10px;'
            f'padding:14px 16px;min-width:120px;text-align:center;flex:1;">'
            f'<div style="font-size:32px;font-weight:800;color:{color};line-height:1.1;">{value}</div>'
            f'<div style="font-size:13px;color:#c6d2e6;margin-top:6px;font-weight:600;">{label}</div>'
            f'<div style="font-size:11px;color:#64748b;margin-top:3px;">{pct:.0f}%</div>'
            f'</div>')
    container = '<div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:center;width:100%;">' + "".join(cards) + '</div>'
    head = (f'<div style="font-size:10px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:.8px;font-weight:700;margin-bottom:8px">{title}</div>') if title else ""
    return f'<div style="display:flex;flex-direction:column;align-items:center;width:100%">{head}{container}</div>'


def treemap_chart(data, size=220, title=None):
    """Simple binary-subdivision treemap sized by value."""
    filtered = [(l, v, c) for l, v, c in data if v and v > 0]
    total = sum(v for _, v, _ in filtered)
    w = max(int(size * 1.35), 260)
    h = max(int(size), 200)

    if total <= 0:
        svg = (f'<svg viewBox="0 0 {w} {h}" width="100%" style="max-width:{w}px">'
               f'<rect x="0" y="0" width="{w}" height="{h}" fill="#0d1729" stroke="#233458"/>'
               f'<text x="{w/2}" y="{h/2}" text-anchor="middle" dominant-baseline="middle" '
               f'fill="#8ea1c2" font-size="11">No data</text></svg>')
    else:
        def layout(items, x, y, bw, bh, horizontal):
            if not items:
                return []
            if len(items) == 1:
                l, v, c = items[0]
                return [{"x": x, "y": y, "w": bw, "h": bh, "label": l, "value": v, "color": c}]
            items_total = sum(v for _, v, _ in items)
            acc = 0
            split_idx = 1
            for i, (_, v, _) in enumerate(items):
                acc += v
                if acc >= items_total / 2:
                    split_idx = i + 1
                    break
            left = items[:split_idx]
            right = items[split_idx:]
            left_total = sum(v for _, v, _ in left)
            ratio = left_total / items_total if items_total else 0.5
            if horizontal:
                lw = bw * ratio
                return (layout(left, x, y, lw, bh, False) +
                        layout(right, x + lw, y, bw - lw, bh, False))
            th = bh * ratio
            return (layout(left, x, y, bw, th, True) +
                    layout(right, x, y + th, bw, bh - th, True))

        rects = layout(filtered, 0, 0, w, h, True)
        parts = []
        for r in rects:
            parts.append(
                f'<rect x="{r["x"]:.1f}" y="{r["y"]:.1f}" width="{r["w"]:.1f}" '
                f'height="{r["h"]:.1f}" fill="{r["color"]}" stroke="#0b1220" stroke-width="1.5"/>'
            )
            if r["w"] > 52 and r["h"] > 30:
                cx = r["x"] + r["w"] / 2
                cy = r["y"] + r["h"] / 2
                pct = r["value"] / total * 100
                max_chars = max(3, int(r["w"] / 7))
                label = r["label"] if len(r["label"]) <= max_chars else r["label"][:max_chars - 1] + "…"
                parts.append(
                    f'<text x="{cx:.1f}" y="{cy - 5:.1f}" text-anchor="middle" '
                    f'fill="#fff" font-size="11" font-weight="700">{label}</text>'
                    f'<text x="{cx:.1f}" y="{cy + 10:.1f}" text-anchor="middle" '
                    f'fill="#fff" font-size="9">{r["value"]} ({pct:.0f}%)</text>'
                )
        svg = (f'<svg viewBox="0 0 {w} {h}" width="100%" style="max-width:{w}px">'
               + "".join(parts) + "</svg>")

    legend = '<ul style="list-style:none;padding:0;margin:6px 0 0;font-size:17.5px;width:100%">'
    for label, value, color in filtered:
        pct = (value / total * 100) if total else 0
        legend += (f'<li style="display:flex;align-items:center;gap:6px;margin:2px 0">'
                   f'<span style="width:8px;height:8px;border-radius:2px;background:{color};flex:0 0 auto"></span>'
                   f'<span style="flex:1;color:#c6d2e6">{label}</span>'
                   f'<span style="color:#8ea1c2">{value} <span style="opacity:.55">({pct:.0f}%)</span></span></li>')
    legend += "</ul>"
    head = (f'<div style="font-size:10px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:.8px;font-weight:700;margin-bottom:4px">{title}</div>') if title else ""
    return f'<div style="display:flex;flex-direction:column;align-items:center">{head}{svg}{legend}</div>'


def radial_chart(data, size=220, title=None):
    """Nightingale / rose chart - sector radius proportional to value."""
    total = sum(v for _, v, _ in data if v and v > 0)
    cx = cy = size / 2
    max_r = size / 2 - 5
    if total <= 0:
        svg = (f'<svg viewBox="0 0 {size} {size}" width="100%" style="max-width:{size}px">'
               f'<circle cx="{cx}" cy="{cy}" r="{max_r*0.7:.1f}" fill="none" stroke="#233458" stroke-width="2"/>'
               f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="middle" '
               f'fill="#8ea1c2" font-size="11">No data</text></svg>')
    else:
        max_val = max(v for _, v, _ in data if v and v > 0) or 1
        parts = []
        start = -math.pi / 2
        for _, value, color in data:
            if not value or value <= 0:
                continue
            angle = (value / total) * 2 * math.pi
            end = start + angle
            r = max_r * (value / max_val)
            x1 = cx + r * math.cos(start); y1 = cy + r * math.sin(start)
            x2 = cx + r * math.cos(end);   y2 = cy + r * math.sin(end)
            large = 1 if angle > math.pi else 0
            parts.append(
                f'<path d="M {cx} {cy} L {x1:.2f} {y1:.2f} A {r} {r} 0 {large} 1 '
                f'{x2:.2f} {y2:.2f} Z" fill="{color}" stroke="#0b1220" stroke-width="1.5"/>'
            )
            start = end
        svg = (f'<svg viewBox="0 0 {size} {size}" width="100%" style="max-width:{size}px">'
               + "".join(parts) + "</svg>")

    legend = '<ul style="list-style:none;padding:0;margin:6px 0 0;font-size:17.5px;width:100%">'
    for label, value, color in data:
        pct = (value / total * 100) if total else 0
        legend += (f'<li style="display:flex;align-items:center;gap:6px;margin:2px 0">'
                   f'<span style="width:8px;height:8px;border-radius:2px;background:{color};flex:0 0 auto"></span>'
                   f'<span style="flex:1;color:#c6d2e6">{label}</span>'
                   f'<span style="color:#8ea1c2">{value} <span style="opacity:.55">({pct:.0f}%)</span></span></li>')
    legend += "</ul>"
    head = (f'<div style="font-size:10px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:.8px;font-weight:700;margin-bottom:4px">{title}</div>') if title else ""
    return f'<div style="display:flex;flex-direction:column;align-items:center">{head}{svg}{legend}</div>'
    
# =========================================================================
# KPI chart helpers: stacked bar, Pareto, time-to-failure scatter
# =========================================================================
def stacked_bar_chart(categories, series, width=1800, height=600, title=None):
    if not categories or not series:
        return '<div class="empty" style="padding:20px;text-align:center;color:#8ea1c2;">No completed data for the selected range.</div>'
    
    n = len(categories)
    # Increase bottom padding if we need to rotate labels
    pad_b = 120 if n > 8 else 80
    pad_l, pad_r, pad_t = 90, 40, 50
    chart_w = width - pad_l - pad_r
    chart_h = height - pad_t - pad_b
    
    totals = [sum(s["values"][i] for s in series) for i in range(n)]
    max_total = max(totals) if totals else 1
    max_total = max_total or 1
    slot_w = chart_w / n
    bar_w = min(100.0, slot_w * 0.75)

    parts = []
    # Y-Axis & Grid
    for k in range(5):
        val = max_total * k / 4
        y = pad_t + chart_h - (val / max_total) * chart_h
        parts.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width-pad_r}" y2="{y:.1f}" stroke="#1e2e4a" stroke-dasharray="4,4"/>')
        parts.append(f'<text x="{pad_l-12}" y="{y+5:.1f}" text-anchor="end" fill="#8ea1c2" font-size="16">{int(val)}</text>')

    # Bars & X-Axis
    for i, cat in enumerate(categories):
        cx = pad_l + slot_w * i + slot_w / 2
        x = cx - bar_w / 2
        bottom = pad_t + chart_h
        for s in series:
            v = s["values"][i]
            if v <= 0: continue
            h = (v / max_total) * chart_h
            y = bottom - h
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="{s["color"]}"/>')
            if h > 24:
                parts.append(f'<text x="{cx:.1f}" y="{y + h/2 + 6:.1f}" text-anchor="middle" fill="#ffffff" font-size="16" font-weight="700">{v}</text>')
            bottom = y
            
        if n > 8:
            # Rotated label for dense data to prevent overlapping
            parts.append(f'<g transform="translate({cx:.1f},{pad_t+chart_h+15}) rotate(-35)"><text x="0" y="0" text-anchor="end" fill="#8ea1c2" font-size="15">{cat}</text></g>')
        else:
            display_cat = cat if len(cat) <= 16 else cat[:15] + "…"
            parts.append(f'<text x="{cx:.1f}" y="{pad_t+chart_h+26}" text-anchor="middle" fill="#8ea1c2" font-size="15">{display_cat}</text>')

    legend = '<div style="display:flex;gap:24px;justify-content:center;margin-top:14px;flex-wrap:wrap;">'
    for s in series:
        legend += (f'<span style="display:flex;align-items:center;gap:8px;font-size:16px;color:#c6d2e6;">'
                   f'<i style="width:18px;height:18px;background:{s["color"]};display:inline-block;border-radius:4px;"></i>'
                   f'{s["name"]}</span>')
    legend += '</div>'
    head = (f'<div style="font-size:14px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:1px;font-weight:700;margin-bottom:10px">{title}</div>') if title else ""
    svg = f'<svg viewBox="0 0 {width} {height}" width="100%" style="max-width:{width}px">' + "".join(parts) + '</svg>'
    return f'<div style="display:flex;flex-direction:column;align-items:center">{head}{svg}{legend}</div>'

def pareto_chart(items, width=1800, height=680, title=None):
    if not items:
        return '<div class="empty" style="padding:20px;text-align:center;color:#8ea1c2;">No failures recorded in the selected range.</div>'
    
    pad_l, pad_r, pad_t, pad_b = 90, 90, 50, 180 # Large bottom pad for rotated labels
    chart_w = width - pad_l - pad_r
    chart_h = height - pad_t - pad_b
    n = len(items)
    max_count = max(c for _, c in items) or 1
    total = sum(c for _, c in items) or 1
    slot_w = chart_w / n
    bar_w = min(80.0, slot_w * 0.7)

    parts = []
    # Left axis (count)
    for k in range(5):
        val = max_count * k / 4
        y = pad_t + chart_h - (val / max_count) * chart_h
        parts.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width-pad_r}" y2="{y:.1f}" stroke="#1e2e4a" stroke-dasharray="4,4"/>')
        parts.append(f'<text x="{pad_l-12}" y="{y+5:.1f}" text-anchor="end" fill="#8ea1c2" font-size="16">{int(val)}</text>')
    # Right axis (cumulative %)
    for k in range(5):
        val = 100 * k / 4
        y = pad_t + chart_h - (k / 4) * chart_h
        parts.append(f'<text x="{width-pad_r+14}" y="{y+5:.1f}" text-anchor="start" fill="#f59e0b" font-size="16">{int(val)}%</text>')

    cum = 0
    line_points = []
    for i, (label, count) in enumerate(items):
        cx = pad_l + slot_w * i + slot_w / 2
        x = cx - bar_w / 2
        h = (count / max_count) * chart_h
        y = pad_t + chart_h - h
        
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="#4f8cff"/>')
        parts.append(f'<text x="{cx:.1f}" y="{y-8:.1f}" text-anchor="middle" fill="#e6ecf7" font-size="16" font-weight="700">{count}</text>')
        
        cum += count
        pct = cum / total * 100.0
        py = pad_t + chart_h - (pct / 100.0) * chart_h
        line_points.append((cx, py))
        
        # Rotated Stock Code Labels (-45 degrees)
        short = label if len(label) <= 22 else label[:21] + "…"
        parts.append(f'<g transform="translate({cx:.1f},{pad_t+chart_h+15}) rotate(-45)"><text x="0" y="0" text-anchor="end" fill="#8ea1c2" font-size="15">{short}</text></g>')
        
        # Cumulative % placed at the bottom, below the rotated text
        parts.append(f'<text x="{cx:.1f}" y="{pad_t+chart_h+140}" text-anchor="middle" fill="#f59e0b" font-size="15" font-weight="700">{pct:.0f}%</text>')

    if len(line_points) > 1:
        d = "M " + " L ".join(f"{x:.1f},{y:.1f}" for x, y in line_points)
        parts.append(f'<path d="{d}" fill="none" stroke="#f59e0b" stroke-width="3.5" stroke-linejoin="round"/>')
    for x, y in line_points:
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="#f59e0b"/>')

    head = (f'<div style="font-size:14px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:1px;font-weight:700;margin-bottom:10px">{title}</div>') if title else ""
    svg = f'<svg viewBox="0 0 {width} {height}" width="100%" style="max-width:{width}px">' + "".join(parts) + '</svg>'
    return (f'<div style="display:flex;flex-direction:column;align-items:center">{head}{svg}'
            f'<div style="margin-top:10px;font-size:14px;color:#8ea1c2;text-align:center;">'
            f'Bars = failure count &nbsp;·&nbsp; Orange line = cumulative %</div></div>')

# =============================================================================================
# Adding more GRAPHs for KPI presentaion
# =============================================================================================

def failure_scatter_chart(points, mttf_days=None, width=720, height=340, title=None):
    """
    points : list of dicts -> {"date": "YYYY-MM-DD", "days": float, "label": str}
    """
    if not points:
        return '<div class="empty" style="padding:20px;text-align:center;color:#8ea1c2;">No failed-ticket duration data in the selected range.</div>'
    pad_l, pad_r, pad_t, pad_b = 55, 25, 30, 46
    chart_w = width - pad_l - pad_r
    chart_h = height - pad_t - pad_b
    n = len(points)
    max_days = max(p["days"] for p in points) * 1.15 or 1.0
    if mttf_days:
        max_days = max(max_days, mttf_days * 1.15)

    def px(i):
        return pad_l + (i / (n - 1)) * chart_w if n > 1 else pad_l + chart_w / 2
    def py(v):
        return pad_t + chart_h - (v / max_days) * chart_h

    parts = []
    for k in range(5):
        val = max_days * k / 4
        y = py(val)
        parts.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width-pad_r}" y2="{y:.1f}" stroke="#1e2e4a" stroke-dasharray="3,3"/>')
        parts.append(f'<text x="{pad_l-8}" y="{y+3:.1f}" text-anchor="end" fill="#8ea1c2" font-size="10">{val:.1f}d</text>')

    if mttf_days:
        my = py(mttf_days)
        parts.append(f'<line x1="{pad_l}" y1="{my:.1f}" x2="{width-pad_r}" y2="{my:.1f}" stroke="#f59e0b" stroke-width="2" stroke-dasharray="6,4"/>')
        parts.append(f'<text x="{width-pad_r-5}" y="{my-6:.1f}" text-anchor="end" fill="#f59e0b" font-size="10" font-weight="700">MTTF {mttf_days:.2f} d</text>')

    for i, p in enumerate(points):
        cx, cy = px(i), py(p["days"])
        tip = f'{p.get("label", "")} · {p["date"]} · {p["days"]:.2f} d'
        parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="4.5" fill="#ef4444" stroke="#fca5a5" stroke-width="1.5"><title>{tip}</title></circle>')

    idxs = [0]
    if n > 2: idxs.append(n // 2)
    if n > 1: idxs.append(n - 1)
    for idx in sorted(set(idxs)):
        x = px(idx)
        label = points[idx].get("date", "")[:10]
        anchor = "start" if idx == 0 else ("end" if idx == n - 1 else "middle")
        parts.append(f'<text x="{x:.1f}" y="{height-14}" text-anchor="{anchor}" fill="#8ea1c2" font-size="10">{label}</text>')

    head = (f'<div style="font-size:11px;color:#8ea1c2;text-align:center;text-transform:uppercase;'
            f'letter-spacing:.8px;font-weight:700;margin-bottom:4px">{title}</div>') if title else ""
    svg = f'<svg viewBox="0 0 {width} {height}" width="100%" style="max-width:{width}px">' + "".join(parts) + '</svg>'
    return f'<div style="display:flex;flex-direction:column;align-items:center">{head}{svg}</div>'

# =============================================================================================================================
    
    


VALID_CHART_TYPES = ("pie", "donut", "hbar", "vbar", "stat", "treemap", "radial")


def normalize_chart_type(raw):
    ct = (raw or "pie").strip().lower()
    return ct if ct in VALID_CHART_TYPES else "pie"


def render_chart(data, size=220, title=None, chart_type="pie"):
    if chart_type == "donut":   return donut_chart(data, size, title)
    if chart_type == "hbar":    return hbar_chart(data, size, title)
    if chart_type == "vbar":    return vbar_chart(data, size, title)
    if chart_type == "stat":    return stat_cards(data, title)
    if chart_type == "treemap": return treemap_chart(data, size, title)
    if chart_type == "radial":  return radial_chart(data, size, title)
    return pie_chart(data, size, title)


def test_time_line_chart(points, width=1100, height=300):
    if not points:
        return (f'<svg viewBox="0 0 {width} {height}" width="100%" style="max-width:{width}px">'
                f'<text x="{width/2}" y="{height/2}" text-anchor="middle" dominant-baseline="middle" '
                f'fill="#8ea1c2" font-size="12">No component test duration data in range</text></svg>')
    pad_left, pad_right, pad_top, pad_bottom = 65, 25, 25, 35
    chart_w = width - pad_left - pad_right
    chart_h = height - pad_top - pad_bottom
    limit_mins = 5 * 24 * 60
    warn_mins = limit_mins * 0.8
    max_val = max(float(limit_mins * 1.15), max((p["duration"] for p in points), default=0.0))
    n = len(points)
    def get_x(i):
        if n == 1: return pad_left + chart_w / 2
        return pad_left + (i / (n - 1)) * chart_w
    def get_y(val):
        capped_val = min(val, max_val)
        return pad_top + chart_h - (capped_val / max_val) * chart_h
    svg_parts = []
    svg_parts.append('<defs><linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">'
                     '<stop offset="0%" stop-color="#4f8cff" stop-opacity="0.35"/>'
                     '<stop offset="100%" stop-color="#4f8cff" stop-opacity="0.0"/></linearGradient>'
                     '<linearGradient id="lineGradient" x1="0" y1="0" x2="1" y2="0">'
                     '<stop offset="0%" stop-color="#3b82f6"/><stop offset="100%" stop-color="#60a5fa"/></linearGradient></defs>')
    svg_parts.append(f'<rect x="0" y="0" width="{width}" height="{height}" fill="#0d1729" rx="8" stroke="#233458" stroke-width="1"/>')
    for s in range(5):
        val = (max_val / 4) * s; y = get_y(val)
        svg_parts.append(f'<line x1="{pad_left}" y1="{y:.1f}" x2="{width - pad_right}" y2="{y:.1f}" stroke="#1e2e4a" stroke-dasharray="3,3" stroke-width="1"/>')
        label = f"{val/1440:.1f}d" if val >= 1440 else (f"{int(val/60)}h" if val >= 60 else f"{int(val)}m")
        svg_parts.append(f'<text x="{pad_left - 8}" y="{y + 3:.1f}" text-anchor="end" fill="#8ea1c2" font-size="10" font-family="Segoe UI, sans-serif">{label}</text>')
    limit_y = get_y(limit_mins)
    svg_parts.append(f'<line x1="{pad_left}" y1="{limit_y:.1f}" x2="{width - pad_right}" y2="{limit_y:.1f}" stroke="#ef4444" stroke-dasharray="6,4" stroke-width="1.5" opacity="0.85"/>')
    svg_parts.append(f'<text x="{width - pad_right - 5}" y="{limit_y - 5:.1f}" text-anchor="end" fill="#ef4444" font-size="9" font-family="Segoe UI, sans-serif">5-Day Limit (7,200m)</text>')
    warn_y = get_y(warn_mins)
    svg_parts.append(f'<line x1="{pad_left}" y1="{warn_y:.1f}" x2="{width - pad_right}" y2="{warn_y:.1f}" stroke="#f59e0b" stroke-dasharray="4,4" stroke-width="1" opacity="0.65"/>')
    svg_parts.append(f'<text x="{width - pad_right - 5}" y="{warn_y - 5:.1f}" text-anchor="end" fill="#f59e0b" font-size="9" font-family="Segoe UI, sans-serif">Warning Threshold (4d)</text>')
    path_points = []
    for i, p in enumerate(points):
        path_points.append(f"{get_x(i):.1f},{get_y(p['duration']):.1f}")
    if len(path_points) > 1:
        first_x = get_x(0); last_x = get_x(n - 1); bottom_y = pad_top + chart_h
        area_d = f"M {first_x:.1f},{bottom_y:.1f} L " + " L ".join(path_points) + f" L {last_x:.1f},{bottom_y:.1f} Z"
        svg_parts.append(f'<path d="{area_d}" fill="url(#areaGradient)"/>')
        line_d = "M " + " L ".join(path_points)
        svg_parts.append(f'<path d="{line_d}" fill="none" stroke="url(#lineGradient)" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>')
    for i, p in enumerate(points):
        cx = get_x(i); cy = get_y(p["duration"]); dur = p["duration"]
        if dur >= limit_mins:
            fill_color = "#ef4444"; stroke_color = "#fca5a5"; status_text = "EXCEEDED 5-Day Limit"
        elif dur >= warn_mins:
            fill_color = "#f59e0b"; stroke_color = "#fef3c7"; status_text = "Approaching Limit (Risk)"
        else:
            fill_color = "#22c55e"; stroke_color = "#dcfce7"; status_text = "Within Normal Limit"
        radius = "5" if dur >= warn_mins else "3.5"
        dur_str = f"{dur:.1f} mins ({dur/1440:.1f} days)" if dur >= 1440 else f"{dur:.1f} mins ({dur/60:.1f} hours)"
        tooltip = (f"Date: {p['date_str']}\nComponent: {p['component']}\nMRS Ticket: {p['mrs']}\n"
                   f"Stock Code: {p['stock']}\nDuration: {dur_str}\nStatus: {status_text}")
        if dur >= warn_mins:
            svg_parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="7" fill="none" stroke="{fill_color}" stroke-width="1.5" opacity="0.7"/>')
        svg_parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{radius}" fill="{fill_color}" stroke="{stroke_color}" stroke-width="1.5" style="cursor:pointer;">'
                         f'<title>{tooltip}</title></circle>')
    if n > 0:
        date_indices = [0]
        if n > 2: date_indices.append(n // 2)
        if n > 1: date_indices.append(n - 1)
        for idx in sorted(set(date_indices)):
            x_pos = get_x(idx); dt_str = points[idx]["date_str"]
            anchor = "start" if idx == 0 else ("end" if idx == n - 1 else "middle")
            svg_parts.append(f'<line x1="{x_pos:.1f}" y1="{pad_top + chart_h}" x2="{x_pos:.1f}" y2="{pad_top + chart_h + 4}" stroke="#233458" stroke-width="1"/>')
            svg_parts.append(f'<text x="{x_pos:.1f}" y="{height - 10}" text-anchor="{anchor}" fill="#8ea1c2" font-size="10" font-family="Segoe UI, sans-serif">{dt_str}</text>')
    return f'<svg viewBox="0 0 {width} {height}" width="100%" style="max-width:100%;border-radius:8px;">' + "".join(svg_parts) + '</svg>'


TAB_PERMISSIONS = {
    "overview":"Overview","my_tickets":"My Dashboard","my_completed":"Completed Tickets",
    "history":"History","kpi":"KPI Presentation","alerts":"Alerts",
    "manage_tickets":"Manage Tickets","manage_users":"Manage Users","tester_db":"Tester DB",
    "tools":"Tools",
}
SECTION_LABELS = {"osv":"OSV","te":"Test Engineering"}
TE_TAB_PERMISSIONS = {
    "te_pie_tickets":"PIE Tickets","te_history":"History","te_dashboard":"Test Dashboard",
    "te_alerts":"Alerts","te_kpi":"KPI","te_jira":"JIRA Search","te_tools":"Tools",
}
TE_ADMIN_TABS = {"te_manage_users":"Manage Users"}
TE_ENDPOINTS = {
    "te_pie_tickets":"te_pie_tickets.index","te_history":"te_history.index",
    "te_dashboard":"te_dashboard.index","te_alerts":"te_alerts.index","te_kpi":"te_kpi.index",
    "te_jira":"te_jira.index","te_tools":"tools_portal.index",
}


def user_can_section(section_key):
    if not session.get("user_id") or section_key not in SECTION_LABELS:
        return False
    if session.get("is_admin"):
        return True
    row = get_db().execute("SELECT allowed FROM section_permissions WHERE user_id=? AND section_key=?",
                           (session["user_id"], section_key)).fetchone()
    return bool(row and row["allowed"])


def section_required(section_key):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                session["requested_section"] = section_key
                return redirect(url_for("login", next=request.path))
            if not user_can_section(section_key):
                abort(403)
            if session.get("active_section") != section_key:
                return redirect(url_for("main_menu"))
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def user_can_te(tab_key):
    if tab_key not in TE_TAB_PERMISSIONS or not session.get("user_id"):
        return False
    if session.get("is_admin"):
        return True
    row = get_db().execute("SELECT allowed FROM te_permissions WHERE user_id=? AND tab_key=?",
                           (session["user_id"], tab_key)).fetchone()
    return bool(row and row["allowed"])


def te_permission_required(tab_key):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                session["requested_section"] = "te"
                return redirect(url_for("login", next=request.path))
            if not user_can_section("te") or not user_can_te(tab_key):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def user_can(tab_key):
    if not session.get("user_id"):
        return False
    if session.get("is_admin"):
        return True
    row = get_db().execute("SELECT allowed FROM user_permissions WHERE user_id=? AND tab_key=?",
                           (session["user_id"], tab_key)).fetchone()
    return bool(row and row["allowed"])


@app.context_processor
def inject_access_helpers():
    return {"user_can": user_can, "user_can_section": user_can_section,
            "user_can_te": user_can_te, "section_labels": SECTION_LABELS}


def permission_required(tab_key):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login", next=request.path))
            if not user_can(tab_key):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def first_allowed_url():
    if session.get("active_section") == "te":
        for key, endpoint in TE_ENDPOINTS.items():
            if user_can_te(key):
                return url_for(endpoint)
        if session.get("is_admin"):
            return url_for("te_pie_tickets.index")
        return url_for("main_menu")
    endpoint_map = {
        "overview":"overview","my_tickets":"my_tickets","my_completed":"my_completed",
        "history":"history","kpi":"admin_kpi","alerts":"admin_alerts",
        "manage_tickets":"admin_tickets","manage_users":"admin_users",
        "tester_db":"tester_db",
        "tools":"tools_portal.index",
    }
    for key in TAB_PERMISSIONS:
        if user_can(key):
            return url_for(endpoint_map[key])
    return url_for("logout")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def enforce_selected_section():
    endpoint = request.endpoint or ""
    public = {"main_menu","choose_section","login","yubikey_otp_login","logout","static"}
    if endpoint in public or endpoint.startswith("static"):
        return None
    if not session.get("user_id"):
        return None
    active = session.get("active_section")
    if active not in SECTION_LABELS:
        return redirect(url_for("main_menu"))
    if active == "te":
        te_allowed = endpoint.startswith("te_") or endpoint in {
            "admin_users","admin_users_add","admin_users_delete",
            "admin_user_categorized_access","admin_user_permissions",
            "admin_user_sections","admin_yubico_config",
            "admin_user_yubikey_otp_register","admin_user_yubikey_clear",
        }
        if not te_allowed:
            return redirect(first_allowed_url())
    if active == "osv" and endpoint.startswith("te_"):
        return redirect(url_for("main_menu"))
    return None


def _clean_yubikey_otp(value):
    return re.sub(r"\s+", "", (value or "").strip().lower())


def _yubikey_public_id(otp):
    return otp[:12]


def _load_yubico_config():
    client_id = YUBICO_CLIENT_ID; secret_key = YUBICO_SECRET_KEY
    if os.path.isfile(YUBICO_CONFIG_PATH):
        try:
            with open(YUBICO_CONFIG_PATH, "r", encoding="utf-8") as handle:
                saved = json.load(handle)
            client_id = (saved.get("client_id") or client_id).strip()
            secret_key = (saved.get("secret_key") or secret_key).strip()
        except (OSError, ValueError, TypeError):
            pass
    return client_id, secret_key


def _yubico_hmac_self_test():
    secret = "mG5be6ZJU1qBGz24yPh/ESM3UdU="
    values = {"status":"OK","t":"2019-06-06T05:14:15Z0369","nonce":"0123456789abcdef",
              "otp":"cccccckdvvulethkhtvkrtbeukiettvfceekurncllcj","sl":"25"}
    return _otp_signature(values, secret) == "iCV9uFJDtuyELQsxFPnR80Yj2XU="


def _save_yubico_config(client_id, secret_key):
    os.makedirs(DATA_DIR, exist_ok=True)
    temporary = YUBICO_CONFIG_PATH + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump({"client_id": client_id, "secret_key": secret_key}, handle)
    os.replace(temporary, YUBICO_CONFIG_PATH)


def _normalize_yubico_secret(secret_key):
    value = urllib.parse.unquote_plus((secret_key or "").strip())
    value = re.sub(r"\s+", "", value); value += "=" * (-len(value) % 4); return value


def _decode_yubico_secret(secret_key):
    normalized = _normalize_yubico_secret(secret_key)
    return base64.b64decode(normalized, validate=True)


def _otp_signature(values, secret_key=None):
    message = "&".join(f"{key}={values[key]}" for key in sorted(values) if key != "h")
    if not secret_key:
        _client_id, secret_key = _load_yubico_config()
    key = _decode_yubico_secret(secret_key)
    return base64.b64encode(hmac.new(key, message.encode("utf-8"), hashlib.sha1).digest()).decode("ascii")


def validate_yubikey_otp(otp):
    otp = _clean_yubikey_otp(otp)
    if not YUBIKEY_OTP_PATTERN.fullmatch(otp):
        return False, "The YubiKey OTP format is invalid.", None
    client_id, secret_key = _load_yubico_config()
    secret_key = _normalize_yubico_secret(secret_key)
    if not client_id or not secret_key:
        return False, "YubiKey OTP is not configured.", None
    if not client_id.isdigit():
        return False, "The Yubico Client ID must contain numbers only.", None
    try:
        _decode_yubico_secret(secret_key)
    except Exception:
        return False, "The YubiKey Secret Key must be the Base64 key supplied by Yubico.", None
    nonce = secrets.token_urlsafe(24).replace("-", "").replace("_", "")[:32]
    params = {"id": client_id, "otp": otp, "nonce": nonce, "timestamp": "1"}
    params["h"] = _otp_signature(params, secret_key)
    url = YUBICO_VERIFY_URL + "?" + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MRS-Ticket-Dashboard/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"YubiCloud validation could not be reached: {exc}", None
    values = {}
    for line in body.splitlines():
        if "=" in line:
            key, value = line.split("=", 1); values[key] = value
    status = values.get("status", "UNKNOWN")
    if not values.get("h"):
        return False, "YubiCloud returned no response signature.", status
    expected_h = _otp_signature(values, secret_key)
    if not hmac.compare_digest(values["h"].strip(), expected_h):
        if status in {"BAD_SIGNATURE", "NO_SUCH_CLIENT"}:
            return False, "The saved Yubico Client ID and Secret Key do not match.", status
        return False, "The YubiCloud response signature could not be verified.", status
    if values.get("nonce") != nonce or values.get("otp") != otp:
        return False, "The YubiCloud validation response did not match this request.", status
    if status != "OK":
        messages = {"REPLAYED_OTP":"This OTP was already used.",
                    "BAD_OTP":"The YubiKey OTP is invalid.",
                    "NO_SUCH_CLIENT":"The configured Yubico Client ID is invalid.",
                    "BAD_SIGNATURE":"The Yubico API secret key is invalid.",
                    "BACKEND_ERROR":"YubiCloud temporarily could not validate the OTP.",
                    "NOT_ENOUGH_ANSWERS":"YubiCloud did not return enough validation responses.",
                    "REPLAYED_REQUEST":"The validation request was replayed."}
        return False, messages.get(status, f"YubiKey validation failed: {status}"), status
    return True, "YubiKey OTP validated.", status


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
        if user:
            session.clear()
            session["user_id"] = user["id"]; session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"]); session["active_section"] = "osv"
            public_id_row = db.execute("SELECT public_id,device_name FROM yubikey_otp_credentials WHERE user_id=? ORDER BY id LIMIT 1", (user["id"],)).fetchone()
            create_session_log(DATA_DIR, session, user_id=user["id"], username=user["username"], is_admin=bool(user["is_admin"]), yubikey_public_id=(public_id_row["public_id"] if public_id_row else None), yubikey_name=(public_id_row["device_name"] if public_id_row else None), yubikey_holder_name=user["username"], ip_address=request.remote_addr or "", user_agent=request.headers.get("User-Agent", ""))
            audit_event(session, "LOGIN_SUCCESS", method=request.method, path=request.path, endpoint=request.endpoint or "", ip_address=request.remote_addr or "")
            return redirect(url_for("overview"))
        flash("User not found.", "error")
    return render_template("login.html", selected_section="osv", selected_section_label="OSV")


@app.route("/logout")
def logout():
    close_session_log(session, reason="LOGOUT")
    session.clear(); flash("Signed out.", "success"); return redirect(url_for("main_menu"))


@app.post("/audit/client-event")
def audit_client_event():
    if not session.get("user_id"):
        return ("", 204)
    body = request.get_json(silent=True) or {}
    allowed = {"CLICK", "NAVIGATION", "FORM_SUBMIT", "FIELD_CHANGE", "WI_STEP_VIEW", "WI_STEP_COMPLETE"}
    event_type = str(body.get("event_type") or "CLICK").upper()
    if event_type not in allowed:
        event_type = "CLIENT_EVENT"
    audit_event(session, event_type, details={
        "label": body.get("label", ""), "element": body.get("element", ""),
        "element_id": body.get("element_id", ""), "href": body.get("href", ""),
        "page": body.get("page", ""), "field": body.get("field", "")
    }, method=request.method, path=request.path, endpoint=request.endpoint or "", ip_address=request.remote_addr or "")
    return ("", 204)


@app.after_request
def audit_server_request(response):
    if session.get("user_id") and request.endpoint not in {"static", "audit_client_event"}:
        event = "PAGE_VIEW" if request.method == "GET" else "SERVER_ACTION"
        details = {"status_code": response.status_code}
        if request.view_args:
            details["object"] = request.view_args
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            safe_fields = {}
            for key in request.form.keys():
                if any(secret in key.lower() for secret in ("password", "otp", "token", "secret")):
                    safe_fields[key] = "[REDACTED]"
                elif key.startswith("item_text_"):
                    safe_fields[key] = request.form.get(key, "")[:500]
                else:
                    values = request.form.getlist(key)
                    safe_fields[key] = values[:50] if len(values) > 1 else (values[0][:500] if values else "")
            details["form"] = safe_fields
            details["uploaded_files"] = [file.filename for file in request.files.values() if file and file.filename][:50]
        audit_event(session, event, result=("SUCCESS" if response.status_code < 400 else "FAILED"), details=details, method=request.method, path=request.path, endpoint=request.endpoint or "", ip_address=request.remote_addr or "")
    return response


@app.route("/")
def main_menu():
    return render_template("main_menu.html")


@app.get("/section/<section_key>")
def choose_section(section_key):
    section_key = (section_key or "").strip().lower()
    if section_key not in SECTION_LABELS:
        abort(404)
    if session.get("user_id"):
        if not user_can_section(section_key):
            flash(f"Your account does not have access to {SECTION_LABELS[section_key]}.", "error")
            return redirect(url_for("main_menu"))
        session["active_section"] = section_key; session["requested_section"] = section_key
        return redirect(first_allowed_url())
    session.clear(); session["requested_section"] = section_key
    return redirect(url_for("login"))


@app.route("/osv")
@section_required("osv")
def home():
    return redirect(url_for("overview"))


@app.route("/overview")
@permission_required("overview")
def overview():
    db = get_db()
    raw = (request.args.get("date") or "").strip()
    try:
        day_str = raw.replace("-", "/")
        day = datetime.datetime.strptime(day_str, "%Y/%m/%d").date() if raw else datetime.date.today()
    except ValueError:
        day = datetime.date.today()
    day_str_fmt = day.strftime("%Y/%m/%d"); day_prefix = day_str_fmt + "%"
    raw_date_val = day.strftime("%Y-%m-%d")

    q = (request.args.get("q") or "").strip()
    sql = "SELECT * FROM tickets WHERE status='available'"; params = []
    if q:
        sql += " AND (stock_code LIKE ? OR mrs_ticket LIKE ? OR serial_number LIKE ? OR mrs_comments LIKE ?)"
        params += [f"%{q}%"]*4
    sql += " ORDER BY stock_code, id"
    raw_available = db.execute(sql, params).fetchall()

    meta_rows = db.execute("SELECT stock_code, category, component_type, tester_name, est_hours FROM stockcode_metadata").fetchall()
    meta_map = {row["stock_code"].strip().lower(): dict(row) for row in meta_rows}

    stock_groups = {}
    for r in raw_available:
        sc = r["stock_code"]; sc_key = sc.strip().lower()
        if sc not in stock_groups:
            meta = meta_map.get(sc_key, {})
            est_per_unit = float(meta.get("est_hours") or 0.0)
            stock_groups[sc] = {"stock_code": sc, "tickets": [], "count": 0,
                                 "category": meta.get("category",""),
                                 "component_type": meta.get("component_type",""),
                                 "tester_name": meta.get("tester_name",""),
                                 "est_per_unit": est_per_unit}
        stock_groups[sc]["tickets"].append(dict(r)); stock_groups[sc]["count"] += 1
    for sc, grp in stock_groups.items():
        if grp["est_per_unit"] > 0:
            grp["total_est_hours"] = round(grp["est_per_unit"] * grp["count"], 1)
        else:
            grp["total_est_hours"] = None
    grouped_tickets = list(stock_groups.values())
    todays = db.execute("SELECT * FROM tickets WHERE created_at LIKE ?", (day_prefix,)).fetchall()
    available_today = sum(1 for t in todays if t["status"] == "available")
    assigned_today = sum(1 for t in todays if t["status"] == "assigned")
    completed_today = sum(1 for t in todays if t["status"] == "completed")
    completed_on_day = db.execute("SELECT COUNT(*) FROM tickets WHERE completed_at LIKE ?", (day_prefix,)).fetchone()[0]

    today_std = datetime.date.today().strftime("%Y/%m/%d")
    ctx = {"day": day_str_fmt, "raw_date_val": raw_date_val, "today": today_std,
           "prev_day": (day - datetime.timedelta(days=1)).strftime("%Y/%m/%d"),
           "next_day": (day + datetime.timedelta(days=1)).strftime("%Y/%m/%d"),
           "is_today": (day == datetime.date.today()),
           "received": len(todays), "available_today": available_today,
           "assigned_today": assigned_today, "completed_today": completed_today,
           "completed_on_day": completed_on_day,
           "grouped_tickets": grouped_tickets, "total_available_count": len(raw_available),
           "q": q}
    return render_template("overview.html", **ctx)


@app.route("/my-tickets")
@permission_required("my_tickets")
def my_tickets():
    db = get_db()
    if session.get("is_admin"):
        rows = db.execute(
            """SELECT t.*, COALESCE(u.username, t.technician_name) AS assigned_technician
               FROM tickets t LEFT JOIN users u ON u.id = t.assigned_to
               WHERE t.status='assigned'
               ORDER BY t.stock_code, t.id"""
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT t.*, COALESCE(u.username, t.technician_name) AS assigned_technician
               FROM tickets t LEFT JOIN users u ON u.id = t.assigned_to
               WHERE t.assigned_to=? AND t.status='assigned'
               ORDER BY t.stock_code, t.id""",
            (session["user_id"],),
        ).fetchall()
    users = db.execute("SELECT id, username FROM users ORDER BY username COLLATE NOCASE").fetchall()
    stock_groups = {}
    for r in rows:
        stock_groups.setdefault(r["stock_code"], {"stock_code": r["stock_code"], "tickets": []})["tickets"].append(dict(r))
    return render_template("my_tickets.html", grouped_tickets=list(stock_groups.values()),
                           users=users, in_progress_count=len(rows), total_count=len(rows),
                           history_options=_history_option_map())


@app.route("/my-completed")
@permission_required("my_completed")
def my_completed():
    db = get_db(); _sync_history_database(db)
    rows = db.execute("SELECT * FROM tickets WHERE assigned_to=? AND status='completed' ORDER BY completed_at DESC, stock_code, id",
                      (session["user_id"],)).fetchall()
    stock_groups = {}
    for r in rows:
        stock_groups.setdefault(r["stock_code"], {"stock_code": r["stock_code"], "tickets": []})["tickets"].append(dict(r))
    return render_template("my_completed.html", grouped_tickets=list(stock_groups.values()), completed_count=len(rows))


# ==== DEV ONLY DELETE-ALL ROUTES ====
@app.post("/admin/tickets/delete-all")
@admin_required
def admin_tickets_delete_all():
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
    db.execute("DELETE FROM tickets"); db.commit()
    flash(f"DEV: Deleted all {count} ticket entries.", "success")
    return redirect(url_for("admin_tickets"))


@app.post("/overview/delete-available")
@admin_required
def overview_delete_available():
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM tickets WHERE status='available'").fetchone()[0]
    db.execute("DELETE FROM tickets WHERE status='available'"); db.commit()
    flash(f"DEV: Deleted all {count} available tickets.", "success")
    return redirect(url_for("overview"))


# =========================================
# FOR DEV PURPOSES< DELETE AFTER PUBLISHED
# =========================================

@app.post("/my-tickets/delete-all")
@admin_required
def my_tickets_delete_all():
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
    db.execute("DELETE FROM tickets")
    db.commit()
    flash(f"DEV: Deleted all {count} ticket entries.", "success")
    return redirect(url_for("my_tickets"))
# ========================================















# ==== END DEV ONLY ====


from fpdf import FPDF
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


class KPIPresentationPDF(FPDF):
    """Landscape dashboard report matching the dark MRS web-app theme."""
    _TEXT_REPLACEMENTS = str.maketrans({
        "\u2014": "-", "\u2013": "-", "\u2212": "-",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2026": "...", "\u00a0": " ", "\u2022": "*",
    })
    BG = (13, 18, 33)
    PANEL = (27, 35, 57)
    PANEL_2 = (31, 41, 67)
    LINE = (53, 67, 96)
    TEXT = (226, 232, 240)
    MUTED = (148, 163, 184)
    BLUE = (79, 140, 255)
    PURPLE = (167, 139, 250)
    GREEN = (34, 197, 94)
    RED = (239, 68, 68)
    AMBER = (245, 158, 11)

    def __init__(self, dept_name="OSV", admin_name="Administrator"):
        super().__init__(orientation="L", unit="mm", format="A4")
        self.dept_name = self.safe_text(dept_name)
        self.admin_name = self.safe_text(admin_name)
        self.alias_nb_pages()
        self.set_margins(12, 25, 12)
        self.set_auto_page_break(auto=True, margin=12)

    @classmethod
    def safe_text(cls, value):
        if value is None:
            return "-"
        text = str(value).translate(cls._TEXT_REPLACEMENTS)
        return text.encode("latin-1", "replace").decode("latin-1")

    def normalize_text(self, text):
        return super().normalize_text(self.safe_text(text))

    def header(self):
        self.set_fill_color(*self.BG)
        self.rect(0, 0, self.w, self.h, "F")
        self.set_fill_color(17, 24, 43)
        self.rect(0, 0, self.w, 22, "F")
        self.set_fill_color(*self.PURPLE)
        self.rect(0, 0, 4, 22, "F")
        self.set_xy(12, 6)
        self.set_font("helvetica", "B", 15)
        self.set_text_color(*self.TEXT)
        self.cell(120, 6, f"{self.dept_name} KPI DASHBOARD", 0, 0, "L")
        self.set_xy(177, 5)
        self.set_font("helvetica", "B", 8)
        self.set_text_color(*self.PURPLE)
        self.cell(108, 5, f"Management sign-off: {self.admin_name}", 0, 1, "R")
        self.set_xy(177, 11)
        self.set_font("helvetica", "", 7.5)
        self.set_text_color(*self.MUTED)
        self.cell(108, 5, f"Generated {now_standard()}", 0, 1, "R")
        self.set_y(27)

    def footer(self):
        self.set_y(-9)
        self.set_draw_color(*self.LINE)
        self.line(12, self.get_y(), self.w - 12, self.get_y())
        self.set_y(-8)
        self.set_font("helvetica", "", 7)
        self.set_text_color(*self.MUTED)
        self.cell(175, 5, f"Confidential | {self.dept_name} On-Site Verification", 0, 0, "L")
        self.cell(98, 5, f"Page {self.page_no()} of {{nb}}", 0, 0, "R")

    def panel(self, x, y, w, h, radius=3, fill=None):
        color = fill or self.PANEL
        self.set_fill_color(*color)
        self.set_draw_color(*self.LINE)
        self.rect(x, y, w, h, "DF")

    def section_title(self, title, subtitle=None, y=None):
        if y is not None:
            self.set_y(y)
        self.set_x(12)
        self.set_font("helvetica", "B", 14)
        self.set_text_color(*self.TEXT)
        self.cell(0, 7, title, 0, 1)
        if subtitle:
            self.set_x(12)
            self.set_font("helvetica", "", 8)
            self.set_text_color(*self.MUTED)
            self.cell(0, 5, subtitle, 0, 1)

    def metric_card(self, x, y, w, label, value, accent):
        self.panel(x, y, w, 22)
        self.set_fill_color(*accent)
        self.rect(x, y, w, 2.5, "F")
        self.set_xy(x + 4, y + 6)
        self.set_font("helvetica", "", 7.5)
        self.set_text_color(*self.MUTED)
        self.cell(w - 8, 4, label.upper(), 0, 1)
        self.set_xy(x + 4, y + 11)
        self.set_font("helvetica", "B", 15)
        self.set_text_color(*self.TEXT)
        self.cell(w - 8, 7, str(value), 0, 0)

    def insight_box(self, x, y, w, title, text, accent=None, h=18):
        self.panel(x, y, w, h, fill=self.PANEL_2)
        if accent:
            self.set_fill_color(*accent)
            self.rect(x, y, 2, h, "F")
        self.set_xy(x + 5, y + 3)
        self.set_font("helvetica", "B", 7.5)
        self.set_text_color(*(accent or self.PURPLE))
        self.cell(w - 10, 4, title.upper(), 0, 1)
        self.set_xy(x + 5, y + 7.5)
        self.set_font("helvetica", "", 7.3)
        self.set_text_color(*self.TEXT)
        self.multi_cell(w - 10, 3.5, text)


def create_chart_image(data_dict, title, chart_type='pie'):
    """Render a pie/donut chart with a clean, modern look."""
    is_pie_like = chart_type in ('pie', 'donut')
    figsize = (4, 3.5) if is_pie_like else (5.5, 3.5)
    fig, ax = plt.subplots(figsize=figsize, subplot_kw=dict(aspect="equal") if is_pie_like else None)
    
    fig.patch.set_facecolor('#111f38')
    ax.set_facecolor('#111f38')

    labels = list(data_dict.keys())
    sizes = list(data_dict.values())
    color_map = {
        'Completed Work': '#22c55e', 'In-Progress (WIP)': '#f59e0b',
        'NTF': '#22c55e', 'Failed': '#ef4444', 'Not Tested': '#f59e0b', 'Pending / WIP': '#4f8cff',
    }
    default_colors = ['#22c55e', '#ef4444', '#3b82f6', '#f59e0b', '#a855f7', '#64748b', '#06b6d4', '#ec4899']
    colors = [color_map.get(l, default_colors[i % len(default_colors)]) for i, l in enumerate(labels)]

    if sum(sizes) == 0:
        labels = ['No Data']; sizes = [1]; colors = ['#cbd5e1']

    if chart_type == 'donut':
        wedges, texts, autotexts = ax.pie(
            sizes, labels=None, autopct='%1.1f%%', startangle=140, colors=colors,
            textprops=dict(color="#dbeafe", fontsize=9), wedgeprops=dict(width=0.4, edgecolor='#111f38')
        )
        plt.setp(autotexts, size=9, weight="bold", color="white")
        ax.legend(wedges, labels, title="Categories", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1), fontsize=9)
    else:
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors,
            textprops=dict(color="#dbeafe", fontsize=9), wedgeprops=dict(width=1, edgecolor='#111f38')
        )
        plt.setp(autotexts, size=9, weight="bold", color="white")

    ax.set_title(title, fontsize=12, fontweight='bold', color='#e6ecf7', pad=12)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=250, transparent=False)
    plt.close(fig)
    buf.seek(0)
    return buf


def create_stacked_bar_image(buckets, title):
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(8, 4))
    fig.patch.set_facecolor('#111f38')
    
    labels = list(buckets.keys())[-10:]
    passed = [buckets[k]["Passed"] for k in labels]
    failed = [buckets[k]["Failed"] for k in labels]
    not_tested = [buckets[k]["Not Tested"] for k in labels]
    
    ax.bar(labels, passed, label='Passed', color='#22c55e')
    ax.bar(labels, failed, bottom=passed, label='Failed', color='#ef4444')
    ax.bar(labels, not_tested, bottom=[i+j for i,j in zip(passed,failed)], label='Not Tested', color='#f59e0b')
    
    ax.set_title(title, fontsize=12, fontweight='bold', pad=15)
    ax.legend(loc='upper right', fontsize=9, frameon=False)
    ax.tick_params(axis='x', rotation=30, labelsize=9, colors='#475569')
    ax.tick_params(axis='y', labelsize=9, colors='#475569')
    
    # Remove top and right spines, add subtle grid
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#cbd5e1')
    ax.spines['bottom'].set_color('#cbd5e1')
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=250)
    plt.close(fig)
    buf.seek(0)
    return buf


def create_pareto_image(items, title):
    import matplotlib.pyplot as plt
    fig, ax1 = plt.subplots(figsize=(8, 4))
    fig.patch.set_facecolor('#111f38')
    
    labels = [i[0][:12] + '..' if len(i[0]) > 12 else i[0] for i in items]
    counts = [i[1] for i in items]
    total = sum(counts) or 1
    cumulative_pct = []
    current_sum = 0
    for c in counts:
        current_sum += c
        cumulative_pct.append((current_sum / total) * 100)

    ax1.bar(labels, counts, color='#4f8cff', width=0.6)
    ax1.set_ylabel('Failure Count', color='#4f8cff', fontsize=10, fontweight='bold')
    ax1.tick_params(axis='x', rotation=35, labelsize=9, colors='#475569')
    ax1.tick_params(axis='y', labelsize=9, colors='#475569')
    ax1.spines['top'].set_visible(False)
    ax1.spines['left'].set_color('#cbd5e1')
    ax1.spines['bottom'].set_color('#cbd5e1')
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    
    ax2 = ax1.twinx()
    ax2.tick_params(colors='#cbd5e1')
    for spine in ax2.spines.values(): spine.set_color('#334155')
    ax2.plot(labels, cumulative_pct, color='#f59e0b', marker='o', ms=4, lw=2)
    ax2.set_ylabel('Cumulative %', color='#f59e0b', fontsize=10, fontweight='bold')
    ax2.set_ylim(0, 105)
    ax2.tick_params(axis='y', labelsize=9, colors='#475569')
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_color('#cbd5e1')
    
    ax1.set_title(title, fontsize=12, fontweight='bold', pad=15)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=250)
    plt.close(fig)
    buf.seek(0)
    return buf


def create_scatter_image(failure_points, mttf_days, title):
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from datetime import datetime
    
    fig, ax = plt.subplots(figsize=(8, 4))
    fig.patch.set_facecolor('#111f38')
    
    dates = [datetime.strptime(p["date"], "%Y-%m-%d") for p in failure_points]
    days = [p["days"] for p in failure_points]
    
    ax.scatter(dates, days, color='#ef4444', s=40, alpha=0.8, edgecolors='white', linewidth=1)
    
    if mttf_days:
        ax.axhline(y=mttf_days, color='#f59e0b', linestyle='--', linewidth=2, label=f'MTTF: {mttf_days:.2f} days')
        ax.legend(fontsize=9, loc='upper right')
        
    ax.set_title(title, fontsize=12, fontweight='bold', pad=15)
    ax.set_ylabel('Days to Failure', fontsize=10, fontweight='bold')
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    ax.tick_params(axis='x', rotation=30, labelsize=9, colors='#475569')
    ax.tick_params(axis='y', labelsize=9, colors='#475569')
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#cbd5e1')
    ax.spines['bottom'].set_color('#cbd5e1')
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=250)
    plt.close(fig)
    buf.seek(0)
    return buf

# ===============================================================================
# Crating Chart Img
# ===============================================================================
def create_stacked_bar_image(buckets, title):
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 3.15))
    fig.patch.set_facecolor('#111f38'); ax.set_facecolor('#111f38')
    ax.tick_params(colors='#cbd5e1')
    for spine in ax.spines.values(): spine.set_color('#334155')
    labels = list(buckets.keys())[-10:] # Limit to 10 for PDF readability
    passed = [buckets[k]["Passed"] for k in labels]
    failed = [buckets[k]["Failed"] for k in labels]
    not_tested = [buckets[k]["Not Tested"] for k in labels]
    
    ax.bar(labels, passed, label='Passed', color='#22c55e')
    ax.bar(labels, failed, bottom=passed, label='Failed', color='#ef4444')
    ax.bar(labels, not_tested, bottom=[i+j for i,j in zip(passed,failed)], label='Not Tested', color='#f59e0b')
    
    ax.set_title(title, fontsize=10, fontweight='bold', color='#e6ecf7')
    legend = ax.legend(loc='upper right', fontsize=8, facecolor='#0d1729', edgecolor='#334155')
    for text in legend.get_texts(): text.set_color('#e6ecf7')
    ax.tick_params(axis='x', rotation=45, labelsize=8)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=170, facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf

def create_pareto_image(items, title):
    import matplotlib.pyplot as plt
    fig, ax1 = plt.subplots(figsize=(7, 3.5))
    fig.patch.set_facecolor('#111f38'); ax1.set_facecolor('#111f38')
    ax1.tick_params(colors='#cbd5e1')
    for spine in ax1.spines.values(): spine.set_color('#334155')
    labels = [i[0][:10] + '..' if len(i[0]) > 10 else i[0] for i in items] # Truncate long names
    counts = [i[1] for i in items]
    total = sum(counts) or 1
    cumulative_pct = []
    current_sum = 0
    for c in counts:
        current_sum += c
        cumulative_pct.append((current_sum / total) * 100)

    ax1.bar(labels, counts, color='#4f8cff')
    ax1.set_ylabel('Failure Count', color='#4f8cff', fontsize=8)
    ax1.tick_params(axis='x', rotation=45, labelsize=8)
    ax1.tick_params(axis='y', labelsize=8)
    
    ax2 = ax1.twinx()
    ax2.tick_params(colors='#cbd5e1')
    for spine in ax2.spines.values(): spine.set_color('#334155')
    ax2.plot(labels, cumulative_pct, color='#f59e0b', marker='o', ms=3, lw=1.5)
    ax2.set_ylabel('Cumulative %', color='#f59e0b', fontsize=8)
    ax2.set_ylim(0, 105)
    ax2.tick_params(axis='y', labelsize=8)
    
    ax1.set_title(title, fontsize=10, fontweight='bold', color='#e6ecf7')
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=170, facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf

def create_scatter_image(failure_points, mttf_days, title):
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from datetime import datetime
    
    fig, ax = plt.subplots(figsize=(7, 3.5))
    fig.patch.set_facecolor('#111f38'); ax.set_facecolor('#111f38')
    ax.tick_params(colors='#cbd5e1')
    for spine in ax.spines.values(): spine.set_color('#334155')
    dates = [datetime.strptime(p["date"], "%Y-%m-%d") for p in failure_points]
    days = [p["days"] for p in failure_points]
    
    ax.scatter(dates, days, color='#ef4444', s=20, alpha=0.7, edgecolors='white', linewidth=0.5)
    
    if mttf_days:
        ax.axhline(y=mttf_days, color='#f59e0b', linestyle='--', linewidth=1.5, label=f'MTTF: {mttf_days:.2f} days')
        ax.legend(fontsize=8)
        
    ax.set_title(title, fontsize=10, fontweight='bold', color='#e6ecf7')
    ax.set_ylabel('Days to Fail', fontsize=8)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    ax.tick_params(axis='x', rotation=30, labelsize=8)
    ax.tick_params(axis='y', labelsize=8)
    
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=170, facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf
# ===============================================================================












@app.route("/admin/kpi/pdf", methods=["GET", "POST"])
@permission_required("kpi")
def admin_kpi_pdf():
    db = get_db()
    admin_name = session.get("username", "Admin")
    dept_name = "OSV"
    comment_labels = {
        "comment_work_breakdown": "Work Breakdown",
        "comment_overall_results": "Overall Test Results",
        "comment_throughput": "Throughput",
        "comment_pareto": "Pareto - Top Failure Contributors",
        "comment_response_time": "Technician Response Time",
    }
    pdf_comments = []
    for field_name, label in comment_labels.items():
        value = (request.values.get(field_name) or "").strip()[:2000]
        if value:
            pdf_comments.append((label, value))
    chart_type = normalize_chart_type(request.values.get("chart"))
    today = datetime.date.today()
    current_week_start = today - datetime.timedelta(days=today.weekday())
    current_week_end = current_week_start + datetime.timedelta(days=6)

    def parse_filter_date(val, default):
        val = (val or "").strip()
        if not val:
            return default
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y"):
            try:
                return datetime.datetime.strptime(val, fmt).date()
            except ValueError:
                pass
        return default

    def parse_db_date(value):
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            serial = float(text)
            if 1 <= serial <= 100000:
                return (datetime.datetime(1899, 12, 30) + datetime.timedelta(days=serial)).date()
        except (ValueError, TypeError, OverflowError):
            pass
        clean = text.replace("T", " ").replace("Z", "").strip()
        for fmt in ("%Y/%m/%d %I:%M:%S %p", "%Y/%m/%d %I:%M %p", "%Y/%m/%d %H:%M:%S",
                    "%Y/%m/%d %H:%M", "%Y/%m/%d",
                    "%Y-%m-%d %I:%M:%S %p", "%Y-%m-%d %I:%M %p", "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p",
                    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y"):
            try:
                return datetime.datetime.strptime(clean, fmt).date()
            except ValueError:
                pass
        try:
            return datetime.datetime.fromisoformat(clean).date()
        except (ValueError, TypeError):
            return None

    def name_key(v):
        return "".join(ch for ch in (v or "").casefold() if ch.isalnum())
    
    
    def parse_db_datetime(value):
        if value is None: return None
        text = str(value).strip()
        if not text: return None
        try:
            serial = float(text)
            if 1 <= serial <= 100000:
                return datetime.datetime(1899, 12, 30) + datetime.timedelta(days=serial)
        except (ValueError, TypeError, OverflowError): pass
        clean = text.replace("T", " ").replace("Z", "").strip()
        for fmt in ("%Y/%m/%d %I:%M:%S %p", "%Y/%m/%d %I:%M %p", "%Y/%m/%d %H:%M:%S",
                    "%Y/%m/%d %H:%M", "%Y/%m/%d",
                    "%Y-%m-%d %I:%M:%S %p", "%Y-%m-%d %I:%M %p", "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p",
                    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y"):
            try:
                return datetime.datetime.strptime(clean, fmt)
            except ValueError:
                pass
        try:
            return datetime.datetime.fromisoformat(clean)
        except (ValueError, TypeError):
            return None
    
    
    
    
    
    
    
    
    

    def name_tokens(v):
        t = "".join(ch if ch.isalnum() else " " for ch in (v or "").casefold())
        return tuple(sorted(p for p in t.split() if p))

    def names_match(a, b):
        if not a or not b:
            return False
        return name_key(a) == name_key(b) or name_tokens(a) == name_tokens(b)

    date_from = parse_filter_date(request.values.get("from"), current_week_start)
    date_to = parse_filter_date(request.values.get("to"), current_week_end)
    if date_from > date_to:
        date_from, date_to = date_to, date_from
    tech_id = (request.values.get("tech") or "").strip()

    users = db.execute("""SELECT id, TRIM(username) AS username FROM users
        WHERE username IS NOT NULL AND TRIM(username) != ''
        ORDER BY username COLLATE NOCASE""").fetchall()

    selected_user_id = None
    selected_tech_name = ""
    if tech_id.startswith("name:"):
        selected_tech_name = tech_id[5:].strip()
    elif tech_id and tech_id != "All Technicians":
        try:
            selected_user_id = int(tech_id)
            selected = next((u for u in users if u["id"] == selected_user_id), None)
            if selected:
                selected_tech_name = selected["username"]
        except ValueError:
            selected_tech_name = tech_id

    db_rows = db.execute("""SELECT t.*,
        NULLIF(TRIM(t.technician_name),'') AS stored_technician,
        NULLIF(TRIM(u.username),'') AS account_technician,
        COALESCE(NULLIF(TRIM(t.technician_name),''), NULLIF(TRIM(u.username),'')) AS technician
        FROM tickets t LEFT JOIN users u ON u.id = t.assigned_to
        WHERE LOWER(TRIM(COALESCE(t.status,''))) != 'available'
           OR t.assigned_to IS NOT NULL
           OR NULLIF(TRIM(t.technician_name),'') IS NOT NULL
           OR NULLIF(TRIM(t.completed_at),'') IS NOT NULL
           OR NULLIF(TRIM(t.test_result),'') IS NOT NULL
        ORDER BY t.id DESC""").fetchall()

    rows = []
    for row in db_rows:
        stored_name = (row["stored_technician"] or "").strip()
        account_name = (row["account_technician"] or "").strip()
        if tech_id and tech_id != "All Technicians":
            id_match = selected_user_id is not None and row["assigned_to"] == selected_user_id
            name_match = (names_match(stored_name, selected_tech_name) or
                          names_match(account_name, selected_tech_name) or
                          selected_tech_name.casefold() in stored_name.casefold() or
                          selected_tech_name.casefold() in account_name.casefold())
            if not (id_match or name_match):
                continue
        event_date = (parse_db_date(row["completed_at"]) or parse_db_date(row["return_time"])
                      or parse_db_date(row["test_started_at"]) or parse_db_date(row["assigned_at"])
                      or parse_db_date(row["created_at"]) or parse_db_date(row["modified"]))
        
        # Safeguard: Force event_date to be a date if it's a datetime
        if isinstance(event_date, datetime.datetime):
            event_date = event_date.date()

        if event_date is None or event_date < date_from or event_date > date_to:
            continue
        rows.append(row)

    def result_category(row):
        raw = (row["test_result"] or "").strip()
        if not raw:
            return "Pending / WIP"
        normalized = " ".join(raw.split())
        folded = normalized.casefold()
        compact = " ".join(folded.replace("-", " ").replace("_", " ").split())
        if folded == "ntf":
            return "NTF"
        if "failed" in folded:
            return "Failed"
        if "no post" in compact and ("no log" in compact or "no logs" in compact):
            return "Failed"
        if compact in {"not tested", "not test", "not run", "untested", "n/a", "na"}:
            return "Not Tested"
        return normalized

    def is_completed(row):
        status = (row["status"] or "").strip().casefold()
        return (status in {"complete", "completed", "done", "closed"}
                or bool((row["completed_at"] or "").strip())
                or bool((row["test_result"] or "").strip()))

    total_work = len(rows)
    completed_count = sum(1 for row in rows if is_completed(row))
    wip_count = total_work - completed_count
    active_techs = {(row["technician"] or "").strip() for row in rows if (row["technician"] or "").strip()}

    result_counts = {}
    tech_map = {}
    for row in rows:
        category = result_category(row)
        result_counts[category] = result_counts.get(category, 0) + 1
        technician = (row["technician"] or "").strip() or "Unassigned"
        tech_counts = tech_map.setdefault(technician, {})
        tech_counts[category] = tech_counts.get(category, 0) + 1

    # ==================================================================
    # Build the PDF
    # ==================================================================
    
    # ==================================================================
    # Build the PDF
    # ==================================================================
    
    # Re-calculate chart data for PDF (matching logic from admin_kpi view)
    from collections import OrderedDict
    buckets = OrderedDict()
    for row in rows:
        if not is_completed(row): continue
        dt = parse_db_datetime(row["completed_at"])
        if not dt: continue
        key = dt.strftime("%Y-%m-%d") if (date_to - date_from).days <= 21 else f"{dt.isocalendar()[0]}-W{dt.isocalendar()[1]:02d}"
        b = buckets.setdefault(key, {"Passed": 0, "Failed": 0, "Not Tested": 0})
        
        raw_res = (row["test_result"] or "").strip().casefold()
        if raw_res == "ntf" or (raw_res and "fail" not in raw_res): b["Passed"] += 1
        elif "fail" in raw_res: b["Failed"] += 1
        else: b["Not Tested"] += 1

    failure_counts = {}
    failure_points = []
    for row in rows:
        raw_res = (row["test_result"] or "").strip().casefold()
        if "fail" in raw_res or ("no post" in raw_res and "no log" in raw_res):
            key = (row["stock_code"] or "Uncategorized").strip()
            failure_counts[key] = failure_counts.get(key, 0) + 1
            
            start = parse_db_datetime(row["test_started_at"] or row["assigned_at"])
            end = parse_db_datetime(row["completed_at"])
            if start and end and end >= start:
                failure_points.append({"date": end.strftime("%Y-%m-%d"), "days": (end - start).total_seconds() / 86400.0})
                
    pareto_items = sorted(failure_counts.items(), key=lambda kv: -kv[1])[:12]
    mttf_days = (sum(p["days"] for p in failure_points) / len(failure_points)) if failure_points else None

    # Generate summaries
    total_t = sum(b["Passed"] + b["Failed"] + b["Not Tested"] for b in buckets.values())
    total_p = sum(b["Passed"] for b in buckets.values())
    total_f = sum(b["Failed"] for b in buckets.values())
    throughput_sum = f"Total Tested: {total_t} | Passed: {total_p} ({(total_p/total_t*100) if total_t else 0:.1f}%) | Failed: {total_f} ({(total_f/total_t*100) if total_t else 0:.1f}%)"
    
    top_code = pareto_items[0][0] if pareto_items else "N/A"
    pareto_sum = f"Top failure contributor: {top_code} ({pareto_items[0][1] if pareto_items else 0} failures). Focus root-cause analysis on the top 20% of these codes."
    mttf_sum = f"Mean Time To Failure (MTTF): {mttf_days:.2f} days. Components falling below this line represent early-life failures." if mttf_days else "No valid failure duration data."

    # Build a compact landscape dashboard using the web-app visual language.
    pdf = KPIPresentationPDF(dept_name=dept_name, admin_name=admin_name)
    pdf.add_page()

    # PAGE 1 - Executive dashboard
    tech_label = selected_tech_name or tech_id if tech_id and tech_id != "All Technicians" else "All Technicians"
    pdf.section_title("Executive Summary", f"Date range: {date_from.strftime('%b %d, %Y')} - {date_to.strftime('%b %d, %Y')}   |   Technician: {tech_label}", 28)
    card_y = 43
    card_w = 64.5
    pdf.metric_card(12, card_y, card_w, "Total Tickets", total_work, pdf.BLUE)
    pdf.metric_card(81.5, card_y, card_w, "Completed", completed_count, pdf.GREEN)
    pdf.metric_card(151, card_y, card_w, "Work In Progress", wip_count, pdf.AMBER)
    pdf.metric_card(220.5, card_y, card_w, "Active Technicians", len(active_techs), pdf.PURPLE)

    pdf_chart_type = "donut" if chart_type in ("donut", "stat", "treemap", "radial") else chart_type
    chart1_buf = create_chart_image({'Completed': completed_count, 'WIP': wip_count}, '', pdf_chart_type)
    chart2_buf = create_chart_image(result_counts if result_counts else {'No Data': 1}, '', pdf_chart_type)
    pdf.panel(12, 70, 132, 74)
    pdf.panel(153, 70, 132, 74)
    pdf.set_xy(17, 74); pdf.set_font("helvetica", "B", 10); pdf.set_text_color(*pdf.TEXT); pdf.cell(120, 5, "Work State Ratio")
    pdf.set_xy(158, 74); pdf.cell(120, 5, "Overall Test Results")
    pdf.image(chart1_buf, x=20, y=80, w=116, h=58)
    pdf.image(chart2_buf, x=161, y=80, w=116, h=58)

    # Compact technician table across the page.
    table_y = 150
    pdf.set_xy(12, table_y)
    pdf.set_font("helvetica", "B", 10); pdf.set_text_color(*pdf.TEXT)
    pdf.cell(0, 6, "Technician Performance", 0, 1)
    cols = [90, 38, 48, 48, 49]
    heads = ["Technician", "Total", "NTF / Passed", "Failed", "Other / WIP"]
    pdf.set_x(12); pdf.set_fill_color(*pdf.PURPLE); pdf.set_text_color(20, 24, 39); pdf.set_font("helvetica", "B", 8)
    for width, head in zip(cols, heads): pdf.cell(width, 7, head, 0, 0, "C", True)
    pdf.ln(7)
    pdf.set_font("helvetica", "", 7.5)
    for index, (tech, counts) in enumerate(sorted(tech_map.items(), key=lambda item: item[0].casefold())):
        total = sum(counts.values())
        pass_count = counts.get("NTF", 0) + counts.get("Passed", 0) + counts.get("passed", 0)
        fail_count = counts.get("Failed", 0) + counts.get("failed", 0)
        other_count = total - pass_count - fail_count
        pdf.set_x(12); pdf.set_fill_color(*(pdf.PANEL_2 if index % 2 == 0 else pdf.PANEL)); pdf.set_text_color(*pdf.TEXT)
        values = [tech, total, pass_count, fail_count, other_count]
        for col_index, (width, value) in enumerate(zip(cols, values)):
            pdf.cell(width, 6, pdf.safe_text(value), 0, 0, "L" if col_index == 0 else "C", True)
        pdf.ln(6)

    # PAGE 2 - Quality insights, two balanced visual panels.
    pdf.add_page()
    pdf.section_title("Quality & Throughput", "Outcome trends and primary failure contributors", 28)
    sb_img = create_stacked_bar_image(buckets, "") if buckets else None
    p_img = create_pareto_image(pareto_items, "") if pareto_items else None
    pdf.panel(12, 43, 132, 105)
    pdf.panel(153, 43, 132, 105)
    pdf.set_xy(17, 48); pdf.set_font("helvetica", "B", 10); pdf.set_text_color(*pdf.TEXT); pdf.cell(122, 5, "Throughput - NTF / Failed / Not Tested")
    pdf.set_xy(158, 48); pdf.cell(122, 5, "Pareto - Top Failure Contributors")
    if sb_img: pdf.image(sb_img, x=18, y=56, w=120, h=62)
    else: pdf.insight_box(18, 62, 120, "No throughput data", "No completed test-result data is available for this filter.", pdf.MUTED, 25)
    if p_img: pdf.image(p_img, x=159, y=56, w=120, h=62)
    else: pdf.insight_box(159, 62, 120, "No failure data", "No failed tickets are available for Pareto analysis.", pdf.MUTED, 25)
    pdf.insight_box(18, 121, 120, "What the data shows", throughput_sum, pdf.BLUE, 21)
    pdf.insight_box(159, 121, 120, "Where to focus", pareto_sum, pdf.AMBER, 21)

    comment_map = dict(pdf_comments)
    pdf.insight_box(12, 154, 86, "Meaning", "Throughput shows completed volume and the result mix across time. Pareto identifies the stock codes creating most failures.", pdf.PURPLE, 25)
    pdf.insight_box(105.5, 154, 86, "Concern", "Investigate periods with rising failures, reduced output, or a small number of stock codes driving most defects.", pdf.RED, 25)
    pdf.insight_box(199, 154, 86, "Recommended action", "Prioritize recurring stock codes, compare tester and process patterns, and assign corrective-action owners.", pdf.GREEN, 25)
    combined_comment = comment_map.get("Throughput") or comment_map.get("Pareto - Top Failure Contributors")
    if combined_comment:
        pdf.insight_box(12, 183, 273, "Report comment", combined_comment, pdf.BLUE, 14)

    # PAGE 3 - Reliability and concise supporting detail.
    pdf.add_page()
    pdf.section_title("Reliability & Supporting Detail", "Time-to-failure distribution and a concise ticket appendix", 28)
    pdf.panel(12, 43, 177, 100)
    pdf.set_xy(17, 48); pdf.set_font("helvetica", "B", 10); pdf.set_text_color(*pdf.TEXT); pdf.cell(165, 5, "Time-to-Failure / MTTF")
    if failure_points:
        s_img = create_scatter_image(failure_points, mttf_days, "")
        pdf.image(s_img, x=18, y=56, w=165, h=63)
    else:
        pdf.insight_box(18, 62, 165, "No reliability data", "No valid failed-ticket duration data is available.", pdf.MUTED, 25)
    pdf.insight_box(18, 122, 165, "Interpretation", mttf_sum, pdf.AMBER, 16)

    # Right-side summary cards remove unused whitespace and keep the report scannable.
    ntf_count = result_counts.get("NTF", 0) + result_counts.get("Passed", 0) + result_counts.get("passed", 0)
    failed_count = result_counts.get("Failed", 0) + result_counts.get("failed", 0)
    pdf.metric_card(198, 43, 87, "NTF / Passed", ntf_count, pdf.GREEN)
    pdf.metric_card(198, 70, 87, "Failed", failed_count, pdf.RED)
    pdf.metric_card(198, 97, 87, "Average MTTF (days)", f"{mttf_days:.2f}" if mttf_days is not None else "N/A", pdf.AMBER)
    pdf.insight_box(198, 124, 87, "Reliability advice", "Review early-life failures below the MTTF line and repeated long-duration failures by stock code.", pdf.PURPLE, 19)

    # Compact appendix with the most recent 18 records; the dashboard remains concise.
    pdf.set_xy(12, 149); pdf.set_font("helvetica", "B", 10); pdf.set_text_color(*pdf.TEXT); pdf.cell(0, 6, "Recent Filtered Tickets (latest 8)", 0, 1)
    widths = [43, 43, 48, 35, 68, 30]
    headers = ["MRS Ticket", "Stock Code", "Technician", "Result", "Completed At", "Days"]
    pdf.set_x(12); pdf.set_fill_color(*pdf.PURPLE); pdf.set_text_color(20, 24, 39); pdf.set_font("helvetica", "B", 7)
    for width, header in zip(widths, headers): pdf.cell(width, 6, header, 0, 0, "C", True)
    pdf.ln(6)
    pdf.set_font("helvetica", "", 6.5)
    for idx, row in enumerate(rows[:8]):
        start_dt = parse_db_datetime(row["test_started_at"] or row["assigned_at"])
        end_dt = parse_db_datetime(row["completed_at"])
        duration = f"{(end_dt-start_dt).total_seconds()/86400:.2f}" if start_dt and end_dt and end_dt >= start_dt else "-"
        completed = pdf.safe_text(row["completed_at"] or "-")[:22]
        values = [row["mrs_ticket"] or "-", row["stock_code"] or "-", row["technician"] or "-", row["test_result"] or "N/A", completed, duration]
        pdf.set_x(12); pdf.set_fill_color(*(pdf.PANEL_2 if idx % 2 == 0 else pdf.PANEL)); pdf.set_text_color(*pdf.TEXT)
        for col_idx, (width, value) in enumerate(zip(widths, values)):
            pdf.cell(width, 4.3, pdf.safe_text(value)[:26], 0, 0, "L" if col_idx in (0, 1, 2, 4) else "C", True)
        pdf.ln(4.3)

    pdf_buf = io.BytesIO()
    pdf_buf.write(pdf.output())
    pdf_buf.seek(0)
    filename = f"OSV_KPI_Report_{admin_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(pdf_buf, mimetype="application/pdf", as_attachment=True, download_name=filename)
    
    
    
    
    
    
    
    
    
    
    
    
    
    # ===========Delete code if new code works==========================
    # pdf = KPIPresentationPDF(dept_name=dept_name, admin_name=admin_name)
    # pdf.set_auto_page_break(auto=True, margin=15)
    # pdf.add_page()

    # # Filter summary bar
    # pdf.set_fill_color(240, 244, 248)
    # pdf.rect(10, 31, 190, 24, "F")
    # pdf.set_xy(12, 33)
    # pdf.set_font("helvetica", "B", 10)
    # pdf.set_text_color(15, 23, 42)
    # filter_desc = f"Date Range: {date_from.strftime('%m/%d/%Y')} to {date_to.strftime('%m/%d/%Y')}"
    # if tech_id and tech_id != "All Technicians":
    #     filter_desc += f"  |  Technician: {selected_tech_name or tech_id}"
    # else:
    #     filter_desc += "  |  Technician: All Technicians"
    # filter_desc += f"  |  Chart: {chart_type.title()}"
    # pdf.cell(0, 5, f"OSV Executive Summary  |  {filter_desc}", 0, 1, "L")

    # pdf.set_xy(12, 40)
    # pdf.set_font("helvetica", "B", 9)
    # pdf.set_text_color(30, 41, 59)
    # summary_line = (f"Total Tickets: {total_work}   |   Completed: {completed_count}"
    #                 f"   |   WIP: {wip_count}   |   Active Techs: {len(active_techs)}")
    # pdf.cell(0, 5, summary_line, 0, 1, "L")

    # pdf_chart_type = chart_type
    # if pdf_chart_type in ("stat", "treemap", "radial"):
    #     pdf_chart_type = "pie"  # PDF fallback

    # work_breakdown_data = {'Completed Work': completed_count, 'In-Progress (WIP)': wip_count}
    # chart1_buf = create_chart_image(work_breakdown_data, 'Work State Ratio', pdf_chart_type)
    # chart2_buf = create_chart_image(
    #     result_counts if result_counts else {'No Data': 1},
    #     'Overall Test Results', pdf_chart_type
    # )
    # pdf.image(chart1_buf, x=15, y=58, w=85)
    # pdf.image(chart2_buf, x=110, y=58, w=85)

    # # Technician performance table
    # pdf.set_y(138)
    # pdf.set_font("helvetica", "B", 11)
    # pdf.set_text_color(15, 23, 42)
    # pdf.cell(0, 6, "Technician Test Result Performance", 0, 1, "L")

    # pdf.set_fill_color(15, 23, 42)
    # pdf.set_text_color(255, 255, 255)
    # pdf.set_font("helvetica", "B", 9)
    # pdf.cell(55, 7, "Technician Name", 1, 0, "L", fill=True)
    # pdf.cell(27, 7, "Total", 1, 0, "C", fill=True)
    # pdf.cell(36, 7, "NTF / Passed", 1, 0, "C", fill=True)
    # pdf.cell(36, 7, "Failed", 1, 0, "C", fill=True)
    # pdf.cell(36, 7, "Other / WIP", 1, 1, "C", fill=True)

    # pdf.set_font("helvetica", "", 9)
    # pdf.set_text_color(30, 41, 59)
    # if tech_map:
    #     fill = False
    #     for tech, counts in sorted(tech_map.items(), key=lambda x: x[0].casefold()):
    #         tot = sum(counts.values())
    #         ntf_pass = (counts.get("NTF", 0) + counts.get("passed", 0) + counts.get("Passed", 0))
    #         failed = counts.get("Failed", 0) + counts.get("failed", 0)
    #         other = tot - (ntf_pass + failed)
    #         pdf.set_fill_color(248, 250, 252) if fill else pdf.set_fill_color(255, 255, 255)
    #         pdf.cell(55, 6, str(tech), 1, 0, "L", fill=fill)
    #         pdf.cell(27, 6, str(tot), 1, 0, "C", fill=fill)
    #         pdf.cell(36, 6, str(ntf_pass), 1, 0, "C", fill=fill)
    #         pdf.cell(36, 6, str(failed), 1, 0, "C", fill=fill)
    #         pdf.cell(36, 6, str(other), 1, 1, "C", fill=fill)
    #         fill = not fill
    # else:
    #     pdf.cell(190, 6, "No technician records found in range.", 1, 1, "C")

    # # Sign-off block
    # pdf.ln(8)
    # pdf.set_font("helvetica", "B", 10)
    # pdf.set_text_color(15, 23, 42)
    # pdf.cell(0, 6, "Department Management Authorization", 0, 1, "L")
    # pdf.set_font("helvetica", "", 9)
    # pdf.set_text_color(100, 116, 139)
    # pdf.cell(0, 5, f"Verified & Approved by: {admin_name} (Authenticated via YubiKey Security)", 0, 1, "L")
    # pdf.cell(0, 5, f"Department: OSV (On-Site Verification)  |  Timestamp: {now_standard()}", 0, 1, "L")

    # pdf_buf = io.BytesIO()
    # pdf_buf.write(pdf.output())
    # pdf_buf.seek(0)
    # filename = (f"OSV_KPI_Report_{admin_name}_"
    #             f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    # return send_file(pdf_buf, mimetype="application/pdf",
    #                  as_attachment=True, download_name=filename)

# ======================================================================================================







@app.route("/admin/kpi/presentation")
@permission_required("kpi")
def admin_kpi_presentation():
    db = get_db()
    chart_type = normalize_chart_type(request.args.get("chart"))
    today = datetime.date.today(); day_prefix = today.strftime("%Y/%m/%d") + "%"
    current_year = today.year; current_month = today.month
    year_prefix = f"{current_year}%"; month_prefix = f"{current_year}/{current_month:02d}%"

    def calc_avg_turnaround_mins(tickets_rows):
        durations = []
        for r in tickets_rows:
            assigned_str = r["assigned_at"]; completed_str = r["completed_at"]
            if not assigned_str or not completed_str: continue
            start_str = r["test_started_at"] if r["test_started_at"] else assigned_str
            dt_start, dt_end = None, None
            for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %H:%M:%S","%Y-%m-%d %H:%M:%S","%m/%d/%Y %I:%M %p"):
                try:
                    if not dt_start: dt_start = datetime.datetime.strptime(start_str.strip(), fmt)
                except ValueError: pass
                try:
                    if not dt_end: dt_end = datetime.datetime.strptime(completed_str.strip(), fmt)
                except ValueError: pass
            if dt_start and dt_end and dt_end >= dt_start:
                durations.append((dt_end - dt_start).total_seconds() / 60.0)
        if not durations: return "-"
        avg_mins = sum(durations) / len(durations)
        if avg_mins < 60: return f"{int(round(avg_mins))}m"
        elif avg_mins < 1440: return f"{int(avg_mins // 60)}h {int(round(avg_mins % 60))}m"
        else: return f"{int(avg_mins // 1440)}d {int((avg_mins % 1440) // 60)}h"

    mtd_completed = db.execute("SELECT * FROM tickets WHERE status='completed' AND completed_at LIKE ?", (month_prefix,)).fetchall()
    ytd_completed = db.execute("SELECT * FROM tickets WHERE status='completed' AND completed_at LIKE ?", (year_prefix,)).fetchall()
    mtd_avg_time = calc_avg_turnaround_mins(mtd_completed)
    ytd_avg_time = calc_avg_turnaround_mins(ytd_completed)
    today_received = db.execute("SELECT COUNT(*) FROM tickets WHERE created_at LIKE ?", (day_prefix,)).fetchone()[0]
    today_completed = db.execute("SELECT COUNT(*) FROM tickets WHERE status='completed' AND completed_at LIKE ?", (day_prefix,)).fetchone()[0]
    mtd_count = len(mtd_completed); ytd_count = len(ytd_completed)
    total_unclaimed = db.execute("SELECT COUNT(*) FROM tickets WHERE status='available'").fetchone()[0]
    total_assigned = db.execute("SELECT COUNT(*) FROM tickets WHERE status='assigned'").fetchone()[0]

    unclaimed_vs_assigned_chart = Markup(render_chart([("Available (Unclaimed)", total_unclaimed, "#4f8cff"),
                                                        ("Assigned", total_assigned, "#f59e0b")],
                                                       size=160, title="Unclaimed Stock vs Assigned Work",
                                                       chart_type=chart_type))
    day_passed = db.execute("SELECT COUNT(*) FROM tickets WHERE test_result='passed' AND completed_at LIKE ?", (day_prefix,)).fetchone()[0]
    day_failed = db.execute("SELECT COUNT(*) FROM tickets WHERE test_result='failed' AND completed_at LIKE ?", (day_prefix,)).fetchone()[0]
    day_not_tested = db.execute("SELECT COUNT(*) FROM tickets WHERE test_result='not_tested' AND completed_at LIKE ?", (day_prefix,)).fetchone()[0]
    day_not_run = db.execute("SELECT COUNT(*) FROM tickets WHERE (status='available' OR (status='assigned' AND test_result IS NULL)) AND (created_at LIKE ? OR assigned_at LIKE ?)", (day_prefix, day_prefix)).fetchone()[0]
    stock_results_today_chart = Markup(render_chart([
        ("Passed", day_passed, "#22c55e"), ("Failed", day_failed, "#ef4444"),
        ("Not Tested", day_not_tested, "#f59e0b"), ("Not Tested / Avail", day_not_run, "#4f8cff")
    ], size=160, title=f"Stock Code Results on {today.strftime('%Y/%m/%d')}", chart_type=chart_type))
    day_avail_count = db.execute("SELECT COUNT(*) FROM tickets WHERE status='available'").fetchone()[0]
    started_testing_count = db.execute("""SELECT COUNT(*) FROM tickets
        WHERE test_started_at IS NOT NULL AND test_started_at != ''
          AND (completed_at IS NULL OR completed_at = '')""").fetchone()[0]
    day_assigned_count = db.execute("""SELECT COUNT(*) FROM tickets
        WHERE status='assigned' AND (test_started_at IS NULL OR test_started_at = '')
          AND (completed_at IS NULL OR completed_at = '')""").fetchone()[0]
    status_dist_today_chart = Markup(render_chart([
        ("Available", day_avail_count, "#4f8cff"),
        ("Assigned", day_assigned_count, "#f59e0b"),
        ("Started Testing", started_testing_count, "#06b6d4"),
        ("Completed", today_completed, "#22c55e")
    ], size=160, title=f"Ticket Status Breakdown ({today.strftime('%Y/%m/%d')})", chart_type=chart_type))

    pass_fail_today_chart = Markup(render_chart([
        ("Passed", day_passed, "#22c55e"), ("Failed", day_failed, "#ef4444")
    ], size=200, title=f"Pass vs Fail ({today.strftime('%Y/%m/%d')})", chart_type=chart_type))
    work_state_today_chart = Markup(render_chart([
        ("Completed", today_completed, "#22c55e"), ("In Progress (WIP)", total_assigned, "#f59e0b")
    ], size=200, title="Work State Today", chart_type=chart_type))
    result_breakdown_today_chart = Markup(render_chart([
        ("Passed", day_passed, "#22c55e"), ("Failed", day_failed, "#ef4444"),
        ("Not Tested", day_not_tested, "#f59e0b")
    ], size=200, title="Result Breakdown Today", chart_type=chart_type))

    tech_daily_rows = db.execute("""
        SELECT u.username,
               SUM(CASE WHEN t.assigned_at LIKE ? THEN 1 ELSE 0 END) AS tickets_claimed,
               SUM(CASE WHEN t.test_result='passed' AND t.completed_at LIKE ? THEN 1 ELSE 0 END) AS passed_count,
               SUM(CASE WHEN t.test_result='failed' AND t.completed_at LIKE ? THEN 1 ELSE 0 END) AS failed_count,
               SUM(CASE WHEN t.status='assigned' AND t.test_started_at IS NOT NULL AND t.test_started_at != '' THEN 1 ELSE 0 END) AS testing_count,
               SUM(CASE WHEN t.status='assigned' AND (t.test_started_at IS NULL OR t.test_started_at = '') THEN 1 ELSE 0 END) AS not_tested_count
        FROM users u JOIN tickets t ON t.assigned_to = u.id
        WHERE t.assigned_at LIKE ? OR t.completed_at LIKE ? OR t.test_started_at LIKE ?
        GROUP BY u.id, u.username
        ORDER BY tickets_claimed DESC, u.username COLLATE NOCASE
    """, (day_prefix, day_prefix, day_prefix, day_prefix, day_prefix, day_prefix)).fetchall()
    technician_today_stats = [{"username": r["username"], "tickets_claimed": r["tickets_claimed"] or 0,
                                "passed_count": r["passed_count"] or 0, "failed_count": r["failed_count"] or 0,
                                "testing_count": r["testing_count"] or 0, "not_tested_count": r["not_tested_count"] or 0}
                               for r in tech_daily_rows]
    active_testing_rows = db.execute("""
        SELECT t.id, t.mrs_ticket, t.stock_code, u.username, t.test_started_at,
               t.serial_number, t.mrs_comments, t.failure_reason, t.wh_location,
               t.part_type, t.part_description, t.quality_disposition
        FROM tickets t LEFT JOIN users u ON t.assigned_to = u.id
        WHERE t.test_started_at IS NOT NULL AND t.test_started_at != ''
          AND (t.completed_at IS NULL OR t.completed_at = '')
        ORDER BY t.test_started_at DESC
    """).fetchall()
    active_testing_list = [{"mrs_ticket": r["mrs_ticket"] or f"Ticket #{r['id']}",
                             "stock_code": r["stock_code"] or "Unknown Stock",
                             "username": r["username"] or "Unassigned",
                             "test_started_at": r["test_started_at"],
                             "serial_number": r["serial_number"] or "-",
                             "mrs_comments": r["mrs_comments"] or "No notes provided.",
                             "part_description": r["part_description"] or r["part_type"] or "-",
                             "wh_location": r["wh_location"] or "-"}
                            for r in active_testing_rows]

    today_iso = today.strftime("%Y-%m-%d")
    duty_rows = db.execute("""
        SELECT d.id, d.title, d.details, d.duty_type, d.priority,
               td.osv_tester, td.location, td.last_maintenance_date
        FROM duties d
        LEFT JOIN tester_database td ON td.id = d.tester_id
        WHERE d.duty_date = ?
        ORDER BY CASE d.priority WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 ELSE 2 END,
                 d.id ASC
    """, (today_iso,)).fetchall()
    current_day_duties = [dict(row) for row in duty_rows]
    if today.weekday() == 4 and not any("clean" in (item.get("title") or "").casefold() for item in current_day_duties):
        current_day_duties.insert(0, {
            "id": None, "title": "Clean Testers", "details": "Friday tester cleaning day",
            "duty_type": "Cleaning", "priority": "Normal", "osv_tester": None,
            "location": None, "last_maintenance_date": None,
        })

    # Plain Python data only. The presentation template serializes this object
    # with Jinja's tojson filter, so Markup, Undefined, row, and chart objects
    # must never be placed in this dictionary.
    total_results_today = day_passed + day_failed + day_not_tested
    finished_today = day_passed + day_failed
    pass_rate_today = (day_passed / finished_today * 100.0) if finished_today else 0.0
    failure_rate_today = (day_failed / finished_today * 100.0) if finished_today else 0.0
    chart_summaries = {
        "grid": {
            "title": "Daily Operations Overview",
            "summary": (
                f"{today_received} received and {today_completed} completed today. "
                f"{total_unclaimed} tickets are available and {total_assigned} are assigned."
            ),
        },
        "results": {
            "title": "Stock Results Today",
            "summary": (
                f"{total_results_today} results recorded: {day_passed} NTF/passed, "
                f"{day_failed} failed, and {day_not_tested} not tested."
            ),
        },
        "status": {
            "title": "Ticket Status Today",
            "summary": (
                f"{day_avail_count} available, {day_assigned_count} assigned but not started, "
                f"{started_testing_count} actively testing, and {today_completed} completed."
            ),
        },
        "unclaimed": {
            "title": "Available vs Assigned",
            "summary": f"{total_unclaimed} available tickets compared with {total_assigned} assigned tickets.",
        },
        "passfail": {
            "title": "NTF / Pass vs Fail",
            "summary": (
                f"{day_passed} NTF/passed and {day_failed} failed. "
                f"Pass rate: {pass_rate_today:.1f}%; failure rate: {failure_rate_today:.1f}%."
            ),
        },
        "workstate": {
            "title": "Work State Today",
            "summary": f"{today_completed} completed today with {total_assigned} currently assigned.",
        },
        "resultbreakdown": {
            "title": "Result Breakdown Today",
            "summary": (
                f"{day_passed} NTF/passed, {day_failed} failed, and {day_not_tested} not tested."
            ),
        },
    }
    return render_template("admin_kpi_presentation.html",
        today_str=today.strftime("%B %d, %Y"),
        today_received=today_received, today_completed=today_completed,
        mtd_count=mtd_count, mtd_avg_time=mtd_avg_time,
        ytd_count=ytd_count, ytd_avg_time=ytd_avg_time,
        unclaimed_vs_assigned_chart=unclaimed_vs_assigned_chart,
        stock_results_today_chart=stock_results_today_chart,
        status_dist_today_chart=status_dist_today_chart,
        pass_fail_today_chart=pass_fail_today_chart,
        work_state_today_chart=work_state_today_chart,
        result_breakdown_today_chart=result_breakdown_today_chart,
        technician_today_stats=technician_today_stats,
        active_testing_list=active_testing_list,
        current_day_duties=current_day_duties,
        chart_summaries=chart_summaries,
        current_year=current_year,
        chart_type=chart_type)












# =========================================================================
# Dynamic KPI insights — narrative-bank design.
# Each panel state has 2–4 complete, hand-written 4-part stories. A
# deterministic RNG seeded by the actual data picks one whole story per
# panel, so the four fields always read as one coherent paragraph, and
# different data produces genuinely different prose (not just swapped
# numbers). Same data always yields the same story for PDF reproducibility.
# =========================================================================
def generate_kpi_insights(
    total_work, completed_count, wip_count, active_techs_count,
    result_counts, tech_map,
    response_stats, response_buckets,
    buckets, bucket_labels, stacked_series,
    pareto_items, failure_points, mttf_days,
    date_from_str, date_to_str,
):
    import hashlib, random

    def rng(*parts):
        blob = "|".join(str(p) for p in parts)
        return random.Random(int(hashlib.sha1(blob.encode()).hexdigest()[:12], 16))

    def pick(r, *narratives):
        return r.choice(narratives)

    def name_list(pairs, max_n=3):
        names = [str(n) for n, _ in pairs[:max_n]]
        if not names: return ""
        if len(names) == 1: return names[0]
        if len(names) == 2: return f"{names[0]} and {names[1]}"
        return ", ".join(names[:-1]) + f", and {names[-1]}"

    def pct(n, d):
        return (n / d * 100.0) if d else 0.0

    insights = {}

    # =====================================================================
    # PANEL 1 — WORK BREAKDOWN
    # =====================================================================
    r = rng("wb", total_work, completed_count, wip_count, active_techs_count)
    wip_pct = pct(wip_count, total_work)
    comp_pct = pct(completed_count, total_work)
    tech_s = "s" if active_techs_count != 1 else ""

    if total_work == 0:
        insights["work_breakdown"] = {
            "what": "No tickets matched this filter, so there is nothing to split between completed and in-progress.",
            "why": "The chart is blank because the data is empty — not because the team is idle.",
            "concern": "None from a performance standpoint; an empty filter routinely produces a misleading KPI.",
            "advice": "Broaden the date range, remove the technician filter, or confirm that completions were recorded on the tickets you expected.",
        }
    elif wip_pct >= 60:
        insights["work_breakdown"] = pick(r,
            {
                "what": f"The queue is dominating: {wip_count} of {total_work} tickets ({wip_pct:.0f}%) are still active against {completed_count} completed across {active_techs_count} technician{tech_s}.",
                "why": f"At this ratio, intake is outrunning throughput — new claims are landing faster than tickets are being closed. Backlog-dominant states are a capacity problem, not a workload spike.",
                "concern": f"With {wip_count} open items, individual stalled tickets disappear inside the aggregate, and aging work quietly distorts turnaround KPI.",
                "advice": f"Triage the oldest in-progress tickets first and pause new claims until WIP drops back below {max(5, total_work // 3)}.",
            },
            {
                "what": f"WIP share stands at {wip_pct:.0f}% of the {total_work} tickets worked this period — only {completed_count} reached a final result.",
                "why": "Read this as a capacity mismatch rather than a workload spike: the completion engine is losing ground to claims instead of keeping pace.",
                "concern": "Left unchecked, the open pool compounds each cycle and blurs which tickets are actually progressing versus silently aging.",
                "advice": "Gate new claims on completion rate, assign an explicit owner to every ticket older than the median, and re-measure in two weeks.",
            },
            {
                "what": f"{wip_count} of {total_work} tickets ({wip_pct:.0f}%) opened in this window remain open against {completed_count} closed.",
                "why": "An ordinary workload burst would not leave this many items open at close of the window — the pattern points to intake outpacing completion, not a temporary peak.",
                "concern": f"Most of the period's work is sitting in an in-progress state where individual tickets can quietly age out without anyone noticing.",
                "advice": "Run an explicit WIP audit, drive the oldest items to a final disposition, and only resume claims after the open pool halves.",
            },
        )
    elif wip_pct >= 35:
        insights["work_breakdown"] = pick(r,
            {
                "what": f"Completion leads ({completed_count}, {comp_pct:.0f}%), but the active pool is still sizable at {wip_count} tickets ({wip_pct:.0f}%) spread across {active_techs_count} technician{tech_s}.",
                "why": "The completion side is winning, but not by enough that the balance feels comfortable — a few stalled tickets would flip the ratio.",
                "concern": "If WIP crosses 50% next period, the chart turns from healthy-busy into backlog-dominant, which is a much harder state to unwind.",
                "advice": "Keep reviewing open tickets daily and prevent WIP from creeping upward across consecutive periods.",
            },
            {
                "what": f"This period finished {completed_count} tickets against {wip_count} still open — a modest but meaningful active backlog.",
                "why": "A completion-leading split is healthy in isolation; the metric that matters is whether the WIP fraction grows in the next window.",
                "concern": f"The {wip_count} open tickets deserve a spot-check — nothing urgent in the aggregate, but individual items can still stall silently.",
                "advice": "Spot-check the oldest three to five in-progress tickets to confirm none have stalled without a note.",
            },
            {
                "what": f"About {comp_pct:.0f}% of the workload closed and {wip_pct:.0f}% is still in flight across {active_techs_count} technician{tech_s}.",
                "why": "Throughput is holding, but the open pool is large enough that a sudden intake spike could tip the balance backward.",
                "concern": "This is a transitional state — healthy on its own, but one slow week away from looking like a backlog problem.",
                "advice": "Maintain the current claim cadence and watch whether the WIP share trends up over the next two periods.",
            },
        )
    elif total_work < 8:
        insights["work_breakdown"] = {
            "what": f"Only {total_work} tickets fall inside this filter — {completed_count} completed and {wip_count} still open.",
            "why": "Percentages on this small a sample swing wildly on individual tickets, so the split is indicative rather than diagnostic.",
            "concern": "Small-sample reads mislead if taken as steady-state performance.",
            "advice": "Widen the date range or remove technician filters until at least 10–15 tickets are in scope before drawing conclusions.",
        }
    else:
        insights["work_breakdown"] = pick(r,
            {
                "what": f"A healthy split: {completed_count} completed ({comp_pct:.0f}%) against {wip_count} still open ({wip_pct:.0f}%), handled by {active_techs_count} technician{tech_s}.",
                "why": "Completion comfortably outweighs WIP — this is the steady-state pattern worth protecting through staffing or intake changes.",
                "concern": "Low concern on the split itself; the meaningful signal would be a sudden WIP spike rather than gradual drift.",
                "advice": "Hold the current cadence. If WIP crosses 35%, that is the cue to slow claims and rebalance.",
            },
            {
                "what": f"Most of this period's work is closed: only {wip_count} of {total_work} tickets ({wip_pct:.0f}%) remain active.",
                "why": "Completions are keeping pace with new work, so the open pool is not meaningfully buffering intake.",
                "concern": "Nothing structural to flag — the completion rate is doing the heavy lifting and the open pool is small enough to stay manageable.",
                "advice": "Keep the completion engine running; this is the pattern to protect when staffing or intake shifts.",
            },
        )

    # =====================================================================
    # PANEL 2 — OVERALL TEST RESULTS
    # =====================================================================
    r = rng("or", total_work, completed_count, len(result_counts), len(pareto_items) if pareto_items else 0)
    ntf = result_counts.get("NTF", 0) + result_counts.get("Passed", 0) + result_counts.get("passed", 0)
    fail = result_counts.get("Failed", 0) + result_counts.get("failed", 0)
    nt = result_counts.get("Not Tested", 0)
    pend = result_counts.get("Pending / WIP", 0)
    tot = ntf + fail + nt + pend
    ntf_pct, fail_pct, nt_pct, pend_pct = pct(ntf, tot), pct(fail, tot), pct(nt, tot), pct(pend, tot)
    pareto_top = pareto_items[0][0] if pareto_items else None

    if tot == 0:
        insights["overall_results"] = {
            "what": "No test results were recorded for this filter.",
            "why": "Without a result mix, product quality and test effectiveness cannot be measured from this chart.",
            "concern": "No quality signal is available in this range — the chart is empty because completions are empty, not because everything passed.",
            "advice": "Verify that test_result is captured on every completion, then re-run with a wider date range.",
        }
    elif fail_pct >= 30:
        insights["overall_results"] = pick(r,
            {
                "what": f"Failure dominates this period: {fail} of {tot} results ({fail_pct:.0f}%) are Failed, with only {ntf} NTF/Passed ({ntf_pct:.0f}%), {nt} Not Tested, and {pend} Pending.",
                "why": f"A failure share above 30% is well past normal variance and is the single strongest quality signal in this chart.",
                "concern": f"{fail} real failures represent product and process risk that cannot be attributed to noise. The longer they sit, the more downstream rework accumulates.",
                "advice": f"Cross-reference these failures with the Pareto chart{(' where ' + pareto_top + ' leads') if pareto_top else ''}, assign a root-cause owner per cluster, and treat this as the top KPI issue for the period.",
            },
            {
                "what": f"{fail} tickets came back Failed out of {tot} results ({fail_pct:.0f}%) — nearly double a healthy baseline, with NTF/Passed at just {ntf} ({ntf_pct:.0f}%).",
                "why": "The failure concentration is too high to be random test variation; something upstream is producing genuinely defective units.",
                "concern": f"Every additional failed ticket compounds cost, delays disposition, and hides in a growing count. {pend} pending items could push the picture further negative once dispositioned.",
                "advice": f"Freeze root-cause investigation on the leading failing stock codes{(' like ' + pareto_top) if pareto_top else ''} and check whether failures cluster on one tester or script version.",
            },
        )
    elif fail_pct >= 15:
        insights["overall_results"] = pick(r,
            {
                "what": f"A mixed period: {fail} Failed ({fail_pct:.0f}%), {ntf} NTF/Passed ({ntf_pct:.0f}%), {nt} Not Tested, and {pend} still Pending across {tot} results.",
                "why": "The failure rate is elevated but not dominant — the chart shows a quality signal worth investigating rather than a crisis.",
                "concern": f"Not Tested ({nt_pct:.0f}%) plus Pending ({pend_pct:.0f}%) represents a large disposition gap that will undercount quality once resolved.",
                "advice": f"Sample recent failures, verify root causes, and confirm whether they cluster by stock code{(' (e.g., ' + pareto_top + ')') if pareto_top else ''}, tester, or test configuration.",
            },
            {
                "what": f"Failures sit at {fail} of {tot} results ({fail_pct:.0f}%) — meaningful but still well below the NTF/Passed count of {ntf} ({ntf_pct:.0f}%).",
                "why": "A failure rate near the mid-teens is the zone where small process adjustments have the largest quality return.",
                "concern": f"The {nt + pend} unresolved dispositions (Not Tested + Pending) will change the denominator once closed, so the current {fail_pct:.0f}% may not be the final picture.",
                "advice": "Close out Not Tested and Pending tickets first, then re-evaluate failure rate with a complete denominator before drawing staffing conclusions.",
            },
        )
    elif (nt_pct + pend_pct) >= 25:
        insights["overall_results"] = pick(r,
            {
                "what": f"Failures are modest ({fail}, {fail_pct:.0f}%), but Not Tested ({nt}, {nt_pct:.0f}%) plus Pending ({pend}, {pend_pct:.0f}%) together make up a large unresolved block of the result mix.",
                "why": "A high unresolved share means the pass/fail ratio on this chart undercounts real quality — the effective result mix is more uncertain than the visible failures suggest.",
                "concern": "Not Tested and Pending tickets often hide blockers (missing parts, skipped steps, or incomplete handoffs) that resurface as failures later if not dispositioned.",
                "advice": "Prioritize a reason-tagging sweep on all Not Tested and Pending tickets, then close the loop so the quality denominator is honest next period.",
            },
            {
                "what": f"The chart is dominated by unresolved work: {nt + pend} of {tot} tickets are Not Tested or Pending, versus only {fail} Failed and {ntf} NTF/Passed.",
                "why": "When unresolved items outweigh genuine results, the quality chart measures throughput debt more than it measures quality.",
                "concern": "Without dispositioning, the same tickets appear unresolved across multiple reporting periods and inflate apparent Not-Tested trends.",
                "advice": "Drive Not Tested and Pending tickets to a final result first; only then use this chart to assess failure rate or pass rate.",
            },
        )
    else:
        insights["overall_results"] = pick(r,
            {
                "what": f"A healthy result mix: {ntf} NTF/Passed ({ntf_pct:.0f}%), {fail} Failed ({fail_pct:.0f}%), {nt} Not Tested, {pend} Pending.",
                "why": "Failure rate is low and NTF/Passed dominates — this is the quality profile you want to protect rather than investigate.",
                "concern": f"The only meaningful watch item is the {nt + pend} unresolved tickets, which should be dispositioned before they age.",
                "advice": "Continue normal test flow and drive any remaining Not Tested or Pending tickets to a final disposition.",
            },
            {
                "what": f"{ntf} of {tot} results ({ntf_pct:.0f}%) are NTF/Passed with failures at only {fail} ({fail_pct:.0f}%).",
                "why": "Low failure rate with a dominant pass share is the operating profile you would want to replicate.",
                "concern": "Low concern; the main risk is complacency, not quality drift.",
                "advice": "Keep the current process in place and monitor for a rising failure share or a growing Pending count.",
            },
        )

    # =====================================================================
    # PANEL 3 — THROUGHPUT (stacked pass/fail over time)
    # =====================================================================
    r = rng("tp", total_work, len(buckets) if buckets else 0,
            sum(b.get("Failed", 0) for b in buckets.values()) if buckets else 0)
    total_tested = sum((b.get("Passed", 0) + b.get("Failed", 0) + b.get("Not Tested", 0)) for b in buckets.values())
    total_passed = sum(b.get("Passed", 0) for b in buckets.values())
    total_failed = sum(b.get("Failed", 0) for b in buckets.values())
    total_nt = sum(b.get("Not Tested", 0) for b in buckets.values())
    tp_pct = pct(total_passed, total_tested)
    tf_pct = pct(total_failed, total_tested)
    tnt_pct = pct(total_nt, total_tested)
    n_buckets = len(bucket_labels)

    # Simple trend delta across halves
    trend_delta = None
    if n_buckets >= 4:
        half = n_buckets // 2
        first = sum(sum(s["values"][:half]) for s in stacked_series)
        second = sum(sum(s["values"][half:]) for s in stacked_series)
        if first > 0:
            trend_delta = (second - first) / first * 100.0

    if total_tested == 0:
        insights["throughput"] = {
            "what": "No completed test records exist in the selected period.",
            "why": "Throughput and pass/fail trends cannot be measured without completed tickets.",
            "concern": "Output and quality trends are unknown for this range — the chart is empty, not quietly flat.",
            "advice": "Expand the date range or confirm that completions are being recorded as expected.",
        }
    elif tf_pct >= 25:
        trend_phrase = ""
        if trend_delta is not None and abs(trend_delta) >= 15:
            trend_phrase = f" Output {'grew' if trend_delta > 0 else 'fell'} {abs(trend_delta):.0f}% from the first half to the second."
        insights["throughput"] = pick(r,
            {
                "what": f"Failures are running hot: {total_failed} of {total_tested} tested components ({tf_pct:.0f}%) failed across {n_buckets} period{'s' if n_buckets != 1 else ''}.{trend_phrase}",
                "why": "A failure rate this high across multiple periods suggests a systemic issue rather than isolated defects — the pattern is not confined to a single week.",
                "concern": "Quality problems at this concentration scale faster than they can be reworked, and staff attention shifts from throughput to diagnosis.",
                "advice": f"Freeze the current flow for the leading failing stock codes{(' (' + pareto_top + ')') if pareto_top else ''}, verify tester setup and script version, and check whether failures cluster on one period or technician.",
            },
            {
                "what": f"{total_failed} failures out of {total_tested} tested ({tf_pct:.0f}%) with only {total_passed} passing ({tp_pct:.0f}%).{trend_phrase}",
                "why": "This is a systemic quality signal, not random variation. Failures this distributed across a period rarely trace back to a single unit.",
                "concern": "Continued failure output erodes confidence in the test process and stresses downstream rework capacity.",
                "advice": "Run a Pareto-focused root-cause sweep on the top failing stock codes before accepting more test volume.",
            },
        )
    elif tf_pct >= 12:
        trend_phrase = ""
        if trend_delta is not None and abs(trend_delta) >= 15:
            trend_phrase = f" Volume {'rose' if trend_delta > 0 else 'dropped'} about {abs(trend_delta):.0f}% between the two halves of the period."
        insights["throughput"] = pick(r,
            {
                "what": f"Pass rate is {tp_pct:.0f}% ({total_passed} of {total_tested}) with {total_failed} failures ({tf_pct:.0f}%).{trend_phrase}",
                "why": "Failures are elevated but not dominant — the signal is worth investigating before it grows into a systemic pattern.",
                "concern": f"The {total_nt} Not Tested tickets ({tnt_pct:.0f}%) are consuming throughput without producing a pass or fail result, which undercounts real quality.",
                "advice": "Sample failed tickets from the highest-failure periods and correlate them with the Pareto leaders to find the common factor.",
            },
            {
                "what": f"A mixed result: {total_passed} passed, {total_failed} failed, {total_nt} not tested across {n_buckets} reporting period{'s' if n_buckets != 1 else ''}.{trend_phrase}",
                "why": "The failure rate sits in the mid-teens — the zone where small process changes produce outsized quality improvements.",
                "concern": "Watch for a rising Not Tested share; it absorbs throughput capacity and disguises the true defect rate.",
                "advice": "Investigate why Not Tested is elevated before adjusting test execution, and check whether the failures follow a specific stock code.",
            },
        )
    elif tnt_pct >= 20:
        insights["throughput"] = pick(r,
            {
                "what": f"{total_nt} of {total_tested} tested components ({tnt_pct:.0f}%) were closed Not Tested — a large share of throughput that produced no test result.",
                "why": "Not Tested at this level typically means real blockers — missing parts, skipped steps, or premature ticket closure — rather than a deliberate decision.",
                "concern": "Each Not Tested ticket consumes a claim slot without validating the component and can mask failures that would otherwise surface here.",
                "advice": "Audit the Not Tested reasons, close the underlying blockers, and re-test a sample of recent Not Tested tickets to confirm nothing has been missed.",
            },
            {
                "what": f"Throughput is running but {total_nt} tickets ({tnt_pct:.0f}%) were marked Not Tested versus {total_passed} passes and {total_failed} fails.",
                "why": "A 20%+ Not Tested share is a coverage problem, not a quality problem — it flatters the pass/fail split by removing items from the denominator.",
                "concern": "Aging Not Tested tickets often resurface as real failures once re-test is attempted.",
                "advice": "Prioritize eliminating blockers that cause Not Tested closures before adding test volume.",
            },
        )
    else:
        trend_phrase = ""
        if trend_delta is not None and abs(trend_delta) >= 15:
            trend_phrase = f" Volume {'grew' if trend_delta > 0 else 'fell'} about {abs(trend_delta):.0f}% across the period."
        insights["throughput"] = pick(r,
            {
                "what": f"Stable throughput: {total_passed} passed ({tp_pct:.0f}%), {total_failed} failed ({tf_pct:.0f}%), {total_nt} not tested across {n_buckets} period{'s' if n_buckets != 1 else ''}.{trend_phrase}",
                "why": "Pass rate is strong and failures are low — quality and volume are both within expected ranges.",
                "concern": "Low concern; the metric worth watching is whether the Not Tested share rises above 15% next period.",
                "advice": "Maintain the current execution cadence and keep the Not Tested share low by resolving blockers early.",
            },
            {
                "what": f"A clean pass rate of {tp_pct:.0f}% ({total_passed} of {total_tested}) with only {total_failed} failures across the period.{trend_phrase}",
                "why": "This is the profile you want to replicate — stable output with quality holding across periods.",
                "concern": "Minimal structural risk; focus on sustaining rather than correcting.",
                "advice": "Keep the current test flow in place and re-run this chart after any staffing or script version change.",
            },
        )

    # =====================================================================
    # PANEL 4 — PARETO (top failure contributors)
    # =====================================================================
    r = rng("par", len(pareto_items) if pareto_items else 0,
            pareto_items[0][1] if pareto_items else 0)
    if not pareto_items:
        insights["pareto"] = {
            "what": "No failed tickets were recorded in the selected range, so there is no failure concentration to plot.",
            "why": "Pareto analysis requires failures to identify the leading stock codes driving quality risk.",
            "concern": "No failure hotspots — either a genuinely clean period or failures are not being logged as test_result='failed'.",
            "advice": "Verify that every failing ticket captures test_result='failed'; otherwise the Pareto is blind to real quality issues.",
        }
    else:
        total_failures = sum(c for _, c in pareto_items)
        top_code, top_count = pareto_items[0]
        top_pct = pct(top_count, total_failures)
        top3 = sum(c for _, c in pareto_items[:3])
        top3_pct = pct(top3, total_failures)
        top5 = sum(c for _, c in pareto_items[:5])
        top5_pct = pct(top5, total_failures)
        top3_names = name_list(pareto_items, 3)

        if top3_pct >= 60:
            insights["pareto"] = pick(r,
                {
                    "what": f"Failures are concentrated: {top3_names} together account for {top3_pct:.0f}% of the {total_failures} failures, with {top_code} alone at {top_count} ({top_pct:.0f}%).",
                    "why": "A top-3 concentration this strong is a textbook Pareto — three fixes would resolve the majority of quality problems.",
                    "concern": f"Every period that passes without correction compounds the same three stock codes as the primary cost driver.",
                    "advice": f"Assign a named root-cause owner to {top_code} first, then the next two. These three investigations deliver the highest quality return available in the data.",
                },
                {
                    "what": f"Three stock codes dominate the failure picture: {top3_names} collectively account for {top3} of {total_failures} failures ({top3_pct:.0f}%).",
                    "why": "Concentrated failure patterns usually trace back to a shared root cause — one tester, script version, or vendor batch can drive most of the chart.",
                    "concern": "The remaining failures still matter, but chasing them before the top 3 are corrected is wasted effort.",
                    "advice": f"Start with {top_code} ({top_count} failures, {top_pct:.0f}% of the total), then check whether the same failure signature appears on {pareto_items[1][0] if len(pareto_items) > 1 else 'the next stock code'}.",
                },
                {
                    "what": f"{top_code} leads at {top_count} failures ({top_pct:.0f}%), and the top 3 stock codes represent {top3_pct:.0f}% of the {total_failures} total.",
                    "why": "The Pareto is unusually sharp here — most of the quality problem sits in a small, addressable set of stock codes.",
                    "concern": f"Failures this concentrated tend to indicate a systematic defect (batch, tester, script) rather than random unit-level variation.",
                    "advice": f"Build a case file around {top_code} first: collect the failure signatures, cross-check tester assignment, and identify whether any single factor repeats.",
                },
            )
        elif top3_pct >= 40:
            insights["pareto"] = pick(r,
                {
                    "what": f"The top 3 stock codes ({top3_names}) account for {top3_pct:.0f}% of the {total_failures} failures, led by {top_code} at {top_count} ({top_pct:.0f}%).",
                    "why": "Moderate Pareto concentration — real leaders exist, but the long tail is not negligible and no single code dominates.",
                    "concern": f"Correcting {top_code} alone would reduce failures by about {top_pct:.0f}%. The remaining {100 - top_pct:.0f}% requires multiple investigations.",
                    "advice": f"Start with {top_code}, but plan parallel investigation of the next 2–4 codes to capture the meaningful long tail rather than chasing one stock code repeatedly.",
                },
                {
                    "what": f"{total_failures} failures spread across {len(pareto_items)} stock codes, with the leading three ({top3_names}) representing {top3_pct:.0f}% of the total.",
                    "why": "A mid-range Pareto means the failure picture is not one problem in disguise — it is a cluster of related but distinct issues.",
                    "concern": "If only the top code is fixed, the remaining failures will still require additional cycles of investigation.",
                    "advice": f"Group the top 5 stock codes ({top5_pct:.0f}% of failures) into one investigation workstream rather than handling them one at a time.",
                },
            )
        else:
            insights["pareto"] = pick(r,
                {
                    "what": f"Failures are spread widely: the top 3 stock codes ({top3_names}) account for only {top3_pct:.0f}% of the {total_failures} total, with {top_code} leading at {top_count} ({top_pct:.0f}%).",
                    "why": "A flat Pareto typically indicates a process-wide or environmental issue rather than a component-specific defect.",
                    "concern": "When no single stock code dominates, fixing one code has limited marginal impact — the whole process needs review.",
                    "advice": "Check shared process elements — tester setup, script version, technician assignment — instead of chasing individual stock codes one at a time.",
                },
                {
                    "what": f"No dominant failure leader: {top_code} tops the chart with {top_count} failures ({top_pct:.0f}%), but {len(pareto_items)} stock codes each contribute to the total.",
                    "why": "A diffuse failure pattern usually points to shared upstream factors — the tester, the environment, or the test procedure itself.",
                    "concern": "Piecemeal fixes per stock code will not move the aggregate much because the signal is spread across many codes.",
                    "advice": "Start with a process audit across the top 5 stock codes together — check tester configuration, script version, and technician assignments in one sweep.",
                },
            )

    # =====================================================================
    # PANEL 5 — RESPONSE TIME
    # =====================================================================
    r = rng("rt", response_stats.get("count", 0),
            response_buckets[-1]["count"] if response_buckets else 0)
    rt_count = response_stats.get("count", 0)
    rt_avg = response_stats.get("average", "—")
    rt_median = response_stats.get("median", "—")
    rt_p90 = response_stats.get("p90", "—")
    slow = next((b["count"] for b in response_buckets if b["label"] == "4h+"), 0)
    slow_pct = pct(slow, rt_count)

    if rt_count == 0:
        insights["response_time"] = {
            "what": "No tickets qualified for response-time analysis — the metric needs both created_at and assigned_at, and excludes transferred tickets.",
            "why": "Response time measures how quickly checked-in work receives a technician; without it, assignment speed is invisible.",
            "concern": "Response performance is unknown for this filter, and slow assignments would not be flagged.",
            "advice": "Verify that assigned_at is populated on every claim and that transfer_count is tracked correctly, then re-run.",
        }
    elif slow_pct >= 20:
        insights["response_time"] = pick(r,
            {
                "what": f"{slow} of {rt_count} tickets ({slow_pct:.0f}%) waited 4 hours or more for first assignment. Average response is {rt_avg} and median is {rt_median}.",
                "why": f"A 4h+ share above 20% is well past a healthy service level and would be visible to requesters as a delay.",
                "concern": f"The average of {rt_avg} hides the slow tail — requesters on those {slow} tickets waited far longer than the headline number suggests.",
                "advice": f"Review staffing coverage during the slow-ticket periods, set a 2-hour SLA alert with a named escalation owner{(' — and check whether slow tickets cluster on ' + pareto_top) if pareto_top else ''}.",
            },
            {
                "what": f"Response-time delay is significant: p90 is {rt_p90}, and {slow} tickets ({slow_pct:.0f}%) took 4+ hours to reach a technician.",
                "why": "Distribution tails this long usually indicate staffing gaps during specific windows rather than a uniformly slow process.",
                "concern": "Slow first-assignment compounds downstream cycle time because every subsequent step starts late.",
                "advice": "Pull the raw tickets from the 4h+ bucket, check whether they cluster on a specific hour, technician, or stock code, and correct the coverage gap.",
            },
        )
    elif slow_pct >= 8:
        insights["response_time"] = pick(r,
            {
                "what": f"Average response is {rt_avg}, median {rt_median}, p90 {rt_p90}. Only {slow} tickets ({slow_pct:.0f}%) exceeded 4 hours.",
                "why": "Headline numbers look healthy, but the small 4h+ tail deserves a spot-check to confirm those tickets were not silently stalled.",
                "concern": "A minority of slow assignments can still erode requester confidence even when the aggregate is fine.",
                "advice": "List the delayed tickets and check whether they cluster on a specific time-of-day, technician, or stock code before adjusting anything.",
            },
            {
                "what": f"Most tickets are responded to quickly: median {rt_median}, average {rt_avg}, p90 {rt_p90}. The 4h+ share is only {slow_pct:.0f}%.",
                "why": "This is a healthy distribution — the bulk of the tail is behaving, and slow tickets are the exception.",
                "concern": "Low concern, but {slow} tickets exceeded 4 hours — worth a name-by-name review if the volume grows.",
                "advice": "Continue current practice; re-check this chart after any staffing change to ensure the tail does not expand.",
            },
        )
    elif rt_count < 5:
        insights["response_time"] = {
            "what": f"Only {rt_count} eligible tickets — the average {rt_avg}, median {rt_median}, and p90 {rt_p90} are indicative but not statistically reliable.",
            "why": "Response-time statistics on this small a sample swing heavily on individual tickets.",
            "concern": "Small-sample reads can mislead if interpreted as steady-state performance.",
            "advice": "Re-run this analysis once more tickets accumulate, or expand the date range to reach at least 10 eligible tickets.",
        }
    else:
        insights["response_time"] = pick(r,
            {
                "what": f"Response time is healthy: median {rt_median}, average {rt_avg}, p90 {rt_p90}. Only {slow} tickets ({slow_pct:.0f}%) took 4+ hours.",
                "why": "Fast first-assignment is doing its job — requesters get a technician quickly and downstream steps start on time.",
                "concern": "Low concern; the healthy majority dominates the distribution.",
                "advice": "Maintain current claim cadence and watch the 4h+ bucket only if staffing levels change.",
            },
            {
                "what": f"Assignment speed is strong this period — median {rt_median}, average {rt_avg}, with the 90th percentile at {rt_p90}.",
                "why": "Both the average and the tail are well under normal SLA expectations, indicating sufficient coverage.",
                "concern": "No structural issue; the metric to protect is the p90, not just the average.",
                "advice": "Keep the current assignment flow in place and re-validate after any intake or shift pattern change.",
            },
        )

    return insights





















@app.route("/admin/kpi")
@permission_required("kpi")
def admin_kpi():
    db = get_db()
    chart_type = normalize_chart_type(request.args.get("chart"))
    today = datetime.date.today()
    current_week_start = today - datetime.timedelta(days=today.weekday())
    current_week_end = current_week_start + datetime.timedelta(days=6)

    def parse_filter_date(value, default):
        value = (value or "").strip()
        if not value: return default
        for fmt in ("%Y-%m-%d","%Y/%m/%d","%m/%d/%Y"):
            try: return datetime.datetime.strptime(value, fmt).date()
            except ValueError: pass
        return default

    def parse_db_date(value):
        if value is None: return None
        text = str(value).strip()
        if not text: return None
        try:
            serial = float(text)
            if 1 <= serial <= 100000:
                return (datetime.datetime(1899,12,30) + datetime.timedelta(days=serial)).date()
        except (ValueError, TypeError, OverflowError): pass
        clean = text.replace("T"," ").replace("Z","").strip()
        formats = ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %I:%M %p","%Y/%m/%d %H:%M:%S","%Y/%m/%d %H:%M","%Y/%m/%d",
                   "%Y-%m-%d %I:%M:%S %p","%Y-%m-%d %I:%M %p","%Y-%m-%d %H:%M:%S.%f","%Y-%m-%d %H:%M:%S",
                   "%Y-%m-%d %H:%M","%Y-%m-%d","%m/%d/%Y %I:%M:%S %p","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M:%S",
                   "%m/%d/%Y %H:%M","%m/%d/%Y","%m-%d-%Y %I:%M:%S %p","%m-%d-%Y %I:%M %p","%m-%d-%Y %H:%M:%S","%m-%d-%Y")
        for fmt in formats:
            try: return datetime.datetime.strptime(clean, fmt).date()
            except ValueError: pass
        try: return datetime.datetime.fromisoformat(clean).date()
        except (ValueError, TypeError): return None

    def name_key(v): return "".join(ch for ch in (v or "").casefold() if ch.isalnum())
    def name_tokens(v):
        t = "".join(ch if ch.isalnum() else " " for ch in (v or "").casefold())
        return tuple(sorted(p for p in t.split() if p))
    def names_match(a, b):
        if not a or not b: return False
        return name_key(a) == name_key(b) or name_tokens(a) == name_tokens(b)

    date_from = parse_filter_date(request.args.get("from"), current_week_start)
    date_to = parse_filter_date(request.args.get("to"), current_week_end)
    if date_from > date_to: date_from, date_to = date_to, date_from
    tech_id = (request.args.get("tech") or "").strip()

    users = db.execute("""SELECT id, TRIM(username) AS username FROM users
        WHERE username IS NOT NULL AND TRIM(username) != ''
        ORDER BY username COLLATE NOCASE""").fetchall()
    kpi_technicians = [{"value": str(u["id"]), "name": u["username"]} for u in users]
    known_keys = {name_key(u["username"]) for u in users}
    for item in db.execute("""SELECT DISTINCT TRIM(technician_name) AS technician_name FROM tickets
        WHERE technician_name IS NOT NULL AND TRIM(technician_name) != ''
        ORDER BY technician_name COLLATE NOCASE""").fetchall():
        tech_name = item["technician_name"]
        if name_key(tech_name) not in known_keys:
            kpi_technicians.append({"value": "name:" + tech_name, "name": tech_name})
            known_keys.add(name_key(tech_name))
    kpi_technicians.sort(key=lambda item: item["name"].casefold())

    selected_user_id = None; selected_tech_name = ""
    if tech_id.startswith("name:"):
        selected_tech_name = tech_id[5:].strip()
    elif tech_id:
        try:
            selected_user_id = int(tech_id)
            selected = next((u for u in users if u["id"] == selected_user_id), None)
            if selected: selected_tech_name = selected["username"]
        except ValueError: pass

    db_rows = db.execute("""SELECT t.*,
        NULLIF(TRIM(t.technician_name),'') AS stored_technician,
        NULLIF(TRIM(u.username),'') AS account_technician,
        COALESCE(NULLIF(TRIM(t.technician_name),''), NULLIF(TRIM(u.username),'')) AS technician
        FROM tickets t LEFT JOIN users u ON u.id = t.assigned_to
        WHERE LOWER(TRIM(COALESCE(t.status,''))) != 'available'
           OR t.assigned_to IS NOT NULL
           OR NULLIF(TRIM(t.technician_name),'') IS NOT NULL
           OR NULLIF(TRIM(t.completed_at),'') IS NOT NULL
           OR NULLIF(TRIM(t.test_result),'') IS NOT NULL
        ORDER BY t.id DESC""").fetchall()

    rows = []
    for row in db_rows:
        stored_name = (row["stored_technician"] or "").strip()
        account_name = (row["account_technician"] or "").strip()
        if tech_id:
            id_match = selected_user_id is not None and row["assigned_to"] == selected_user_id
            name_match = names_match(stored_name, selected_tech_name) or names_match(account_name, selected_tech_name)
            if not (id_match or name_match): continue
        event_date = (parse_db_date(row["completed_at"]) or parse_db_date(row["return_time"])
                      or parse_db_date(row["test_started_at"]) or parse_db_date(row["assigned_at"])
                      or parse_db_date(row["created_at"]) or parse_db_date(row["modified"]))
        if event_date is None or event_date < date_from or event_date > date_to: continue
        rows.append(row)

    def result_category(row):
        raw = (row["test_result"] or "").strip()
        if not raw: return "Pending / WIP"
        normalized = " ".join(raw.split()); folded = normalized.casefold()
        compact = " ".join(folded.replace("-", " ").replace("_", " ").split())
        if folded == "ntf": return "NTF"
        if "failed" in folded: return "Failed"
        if "no post" in compact and ("no log" in compact or "no logs" in compact): return "Failed"
        if compact in {"not tested","not test","not run","untested","n/a","na"}: return "Not Tested"
        return normalized

    def is_completed(row):
        status = (row["status"] or "").strip().casefold()
        return status in {"complete","completed","done","closed"} or bool((row["completed_at"] or "").strip()) or bool((row["test_result"] or "").strip())

    total_work = len(rows)
    completed_count = sum(1 for row in rows if is_completed(row))
    wip_count = total_work - completed_count
    active_techs = {(row["technician"] or "").strip() for row in rows if (row["technician"] or "").strip()}
    date_from_str = date_from.isoformat(); date_to_str = date_to.isoformat()
    display_from = date_from.strftime("%Y/%m/%d"); display_to = date_to.strftime("%Y/%m/%d")
    work_pie = Markup(render_chart([("Completed Work", completed_count, "#22c55e"),
                                     ("In Progress (WIP)", wip_count, "#f59e0b")],
                                    size=208, title=f"Work State Ratio ({display_from} to {display_to})",
                                    chart_type=chart_type))
    palette = ["#22c55e","#ef4444","#f59e0b","#4f8cff","#a855f7","#06b6d4","#eab308","#ec4899","#14b8a6",
               "#f97316","#8b5cf6","#84cc16","#0ea5e9","#d946ef","#64748b"]
    preferred_order = ["NTF", "Failed", "Not Tested", "Pending / WIP"]
    result_counts = {}; tech_map = {}
    for row in rows:
        category = result_category(row)
        result_counts[category] = result_counts.get(category, 0) + 1
        technician = (row["technician"] or "").strip() or "Unassigned"
        tech_counts = tech_map.setdefault(technician, {})
        tech_counts[category] = tech_counts.get(category, 0) + 1

    def ordered_categories(counts):
        present = [name for name in preferred_order if counts.get(name, 0) > 0]
        other = sorted((name for name, count in counts.items() if count > 0 and name not in preferred_order), key=str.casefold)
        return present + other

    category_colors = {}
    for index, category in enumerate(ordered_categories(result_counts)):
        if category == "NTF": category_colors[category] = "#22c55e"
        elif category == "Failed": category_colors[category] = "#ef4444"
        elif category == "Not Tested": category_colors[category] = "#f59e0b"
        elif category == "Pending / WIP": category_colors[category] = "#4f8cff"
        else: category_colors[category] = palette[(index + 4) % len(palette)]
    overall_data = [(category, result_counts[category], category_colors[category]) for category in ordered_categories(result_counts)]
    overall_results_pie = Markup(render_chart(overall_data, size=160, title="Overall Test Results", chart_type=chart_type))
    tech_results_charts = []
    for technician, counts in sorted(tech_map.items(), key=lambda item: item[0].casefold()):
        categories = ordered_categories(counts); chart_data = []; summary = []
        for index, category in enumerate(categories):
            color = category_colors.get(category, palette[index % len(palette)])
            chart_data.append((category, counts[category], color))
            summary.append({"label": category, "count": counts[category]})
        tech_results_charts.append({"username": technician, "result_summary": summary,
                                     "chart": Markup(render_chart(chart_data, size=169, chart_type=chart_type))})
    result_group_styles = {
        "NTF": {"text_color":"#86efac","border_color":"rgba(34,197,94,.50)","background":"rgba(34,197,94,.06)","row_background":"rgba(34,197,94,.035)","badge_background":"rgba(34,197,94,.18)"},
        "Failed": {"text_color":"#fca5a5","border_color":"rgba(239,68,68,.55)","background":"rgba(239,68,68,.07)","row_background":"rgba(239,68,68,.04)","badge_background":"rgba(239,68,68,.20)"},
        "Not Tested": {"text_color":"#fcd34d","border_color":"rgba(245,158,11,.50)","background":"rgba(245,158,11,.06)","row_background":"rgba(245,158,11,.035)","badge_background":"rgba(245,158,11,.18)"},
        "Pending / WIP": {"text_color":"#93c5fd","border_color":"rgba(79,140,255,.50)","background":"rgba(79,140,255,.06)","row_background":"rgba(79,140,255,.035)","badge_background":"rgba(79,140,255,.18)"},
    }
    default_result_style = {"text_color":"#c4b5fd","border_color":"rgba(168,85,247,.50)","background":"rgba(168,85,247,.06)","row_background":"rgba(168,85,247,.035)","badge_background":"rgba(168,85,247,.18)"}
    result_group_order = {"NTF":0,"Failed":1,"Not Tested":2,"Pending / WIP":99}

    kpi_group_map = {}; kpi_ticket_details = {}
    for row in rows:
        ticket = dict(row)
        stock_code = (ticket.get("stock_code") or "Uncategorized").strip() or "Uncategorized"
        category = result_category(row)
        stock_group = kpi_group_map.setdefault(stock_code, {"stock_code": stock_code, "result_map": {}, "count": 0})
        stock_group["result_map"].setdefault(category, []).append(ticket)
        stock_group["count"] += 1
        if (ticket.get("test_result") or "").strip().casefold() == "ntf":
            ticket["failure_reason"] = ""
        kpi_ticket_details[str(ticket["id"])] = ticket

    def parse_db_date(value):
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            serial = float(text)
            if 1 <= serial <= 100000:
                return (datetime.datetime(1899, 12, 30) + datetime.timedelta(days=serial)).date()
        except (ValueError, TypeError, OverflowError):
            pass
        clean = text.replace("T", " ").replace("Z", "").strip()
        for fmt in ("%Y/%m/%d %I:%M:%S %p", "%Y/%m/%d %I:%M %p", "%Y/%m/%d %H:%M:%S",
                    "%Y/%m/%d %H:%M", "%Y/%m/%d",
                    "%Y-%m-%d %I:%M:%S %p", "%Y-%m-%d %I:%M %p", "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p",
                    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y"):
            try:
                return datetime.datetime.strptime(clean, fmt).date()
            except ValueError:
                pass
        try:
            return datetime.datetime.fromisoformat(clean).date()
        except (ValueError, TypeError):
            return None

    def parse_db_datetime(value):
        if value is None: return None
        text = str(value).strip()
        if not text: return None
        try:
            serial = float(text)
            if 1 <= serial <= 100000:
                return datetime.datetime(1899, 12, 30) + datetime.timedelta(days=serial)
        except (ValueError, TypeError, OverflowError): pass
        clean = text.replace("T", " ").replace("Z", "").strip()
        for fmt in ("%Y/%m/%d %I:%M:%S %p", "%Y/%m/%d %I:%M %p", "%Y/%m/%d %H:%M:%S",
                    "%Y/%m/%d %H:%M", "%Y/%m/%d",
                    "%Y-%m-%d %I:%M:%S %p", "%Y-%m-%d %I:%M %p", "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p",
                    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y"):
            try:
                return datetime.datetime.strptime(clean, fmt)
            except ValueError:
                pass
        try:
            return datetime.datetime.fromisoformat(clean)
        except (ValueError, TypeError):
            return None

    def format_duration(seconds):
        if seconds is None: return "-"
        seconds = max(0, int(round(seconds)))
        if seconds < 60: return f"{seconds}s"
        if seconds < 3600: return f"{seconds // 60}m"
        if seconds < 86400: return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
        return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"

    response_seconds = []
    for row in rows:
        if int(row["transfer_count"] or 0) != 0: continue
        created_dt = parse_db_datetime(row["created_at"]); assigned_dt = parse_db_datetime(row["assigned_at"])
        if created_dt is None or assigned_dt is None: continue
        elapsed = (assigned_dt - created_dt).total_seconds()
        if elapsed >= 0: response_seconds.append(elapsed)
    response_seconds.sort()

    def percentile(values, fraction):
        if not values: return None
        if len(values) == 1: return values[0]
        position = (len(values) - 1) * fraction
        lower = int(math.floor(position)); upper = int(math.ceil(position))
        if lower == upper: return values[lower]
        return values[lower] + (values[upper] - values[lower]) * (position - lower)

    response_stats = {
        "count": len(response_seconds),
        "average": format_duration(sum(response_seconds) / len(response_seconds)) if response_seconds else "-",
        "median": format_duration(percentile(response_seconds, 0.50)),
        "minimum": format_duration(response_seconds[0] if response_seconds else None),
        "maximum": format_duration(response_seconds[-1] if response_seconds else None),
        "p90": format_duration(percentile(response_seconds, 0.90)),
    }
    bucket_defs = [("0-15m",0,15*60),("15-30m",15*60,30*60),("30-60m",30*60,60*60),
                   ("1-2h",60*60,2*3600),("2-4h",2*3600,4*3600),("4h+",4*3600,None)]
    response_buckets = []
    if response_seconds:
        bucket_counts = []
        for label, lower, upper in bucket_defs:
            count = sum(1 for value in response_seconds if value >= lower and (upper is None or value < upper))
            bucket_counts.append((label, count))
        max_count = max(count for _, count in bucket_counts) or 1
        response_buckets = [{"label": label, "count": count, "percent": round(count / max_count * 100, 1)}
                            for label, count in bucket_counts]

    kpi_stock_groups = []
    for stock_code in sorted(kpi_group_map, key=str.casefold):
        stock_group = kpi_group_map[stock_code]; result_groups = []
        category_names = sorted(stock_group["result_map"],
                                key=lambda name: (result_group_order.get(name, 10), name.casefold()))
        for category in category_names:
            category_tickets = stock_group["result_map"][category]
            category_tickets.sort(key=lambda item: item.get("id") or 0, reverse=True)
            style = result_group_styles.get(category, default_result_style)
            result_groups.append({"label": category, "count": len(category_tickets),
                                   "tickets": category_tickets, **style})
        kpi_stock_groups.append({"stock_code": stock_code, "count": stock_group["count"],
                                  "result_groups": result_groups})


     # =====================================================================
    # KPI charts: Weekly throughput, Pareto of failures, Time-to-failure
    # =====================================================================
    from collections import OrderedDict

    def _chart_group(row):
        """Map a ticket to Passed / Failed / Not Tested for the new KPI charts."""
        raw = (row["test_result"] or "").strip().casefold()
        if not raw:
            return "Not Tested"
        compact = " ".join(raw.replace("-", " ").replace("_", " ").split())
        if compact == "ntf":
            return "Passed"          # No Trouble Found = pass
        if "fail" in compact:
            return "Failed"
        if "no post" in compact and ("no log" in compact or "no logs" in compact):
            return "Failed"
        if compact in {"not tested", "not test", "not run", "untested", "n/a", "na"}:
            return "Not Tested"
        return "Passed"

    range_days = max(1, (date_to - date_from).days)
    use_daily = range_days <= 21

    # Chart 1 — Weekly / daily stacked pass/fail throughput
    buckets = OrderedDict()
    for row in rows:
        if not is_completed(row):
            continue
        dt = parse_db_datetime(row["completed_at"])
        if not dt:
            continue
        if use_daily:
            key = dt.strftime("%Y-%m-%d")
        else:
            iso_year, iso_week, _ = dt.isocalendar()
            key = f"{iso_year}-W{iso_week:02d}"
        b = buckets.setdefault(key, {"Passed": 0, "Failed": 0, "Not Tested": 0})
        b[_chart_group(row)] += 1

    # Cap to the most recent 14 buckets so labels stay readable
    bucket_labels = list(buckets.keys())[-14:]
    stacked_series = [
        {"name": "Passed",     "values": [buckets[k]["Passed"]     for k in bucket_labels], "color": "#22c55e"},
        {"name": "Failed",     "values": [buckets[k]["Failed"]     for k in bucket_labels], "color": "#ef4444"},
        {"name": "Not Tested", "values": [buckets[k]["Not Tested"] for k in bucket_labels], "color": "#f59e0b"},
    ]
    stacked_chart_html = Markup(stacked_bar_chart(
        bucket_labels, stacked_series, width=936, height=468,
        title=f"Throughput — {'Daily' if use_daily else 'Weekly'} Pass / Fail / Not Tested"))

    # Chart 2 — Pareto of top failure contributors (by stock code)
    failure_counts = {}
    for row in rows:
        if _chart_group(row) != "Failed":
            continue
        key = (row["stock_code"] or "Uncategorized").strip() or "Uncategorized"
        failure_counts[key] = failure_counts.get(key, 0) + 1
    pareto_items = sorted(failure_counts.items(), key=lambda kv: -kv[1])[:12]
    pareto_chart_html = Markup(pareto_chart(pareto_items, width=936, height=468, title="Top Failure Contributors — Pareto"))

    # Chart 3 — Time-to-failure scatter + MTTF
    failure_points = []
    for row in rows:
        if _chart_group(row) != "Failed":
            continue
        start = parse_db_datetime(row["test_started_at"] or row["assigned_at"])
        end = parse_db_datetime(row["completed_at"])
        if not start or not end or end < start:
            continue
        days = (end - start).total_seconds() / 86400.0
        failure_points.append({
            "date": end.strftime("%Y-%m-%d"),
            "days": round(days, 3),
            "label": row["mrs_ticket"] or "",
        })
    failure_points.sort(key=lambda p: p["date"])
    mttf_days = (sum(p["days"] for p in failure_points) / len(failure_points)) if failure_points else None
    failure_scatter_html = Markup(failure_scatter_chart(
        failure_points, mttf_days=mttf_days, width=936, height=442, title="Time-to-Failure Distribution (MTTF)"))

    # =====================================================================
    # Generate dynamic summary texts for the UI and PDF
    # =====================================================================
    total_throughput = sum(totals) if 'totals' in locals() else sum(b["Passed"] + b["Failed"] + b["Not Tested"] for b in buckets.values())
    total_passed = sum(b["Passed"] for b in buckets.values())
    total_failed = sum(b["Failed"] for b in buckets.values())
    pass_rate = (total_passed / total_throughput * 100) if total_throughput > 0 else 0
    fail_rate = (total_failed / total_throughput * 100) if total_throughput > 0 else 0

    throughput_summary = (
        f"During the selected period ({display_from} to {display_to}), a total of {total_throughput} components were tested. "
        f"{total_passed} passed ({pass_rate:.1f}%), {total_failed} failed ({fail_rate:.1f}%), "
        f"and {total_throughput - total_passed - total_failed} were not tested. "
        f"Use this chart to track daily or weekly defect yield rates."
    )

    top_failure_code = pareto_items[0][0] if pareto_items else "N/A"
    top_failure_count = pareto_items[0][1] if pareto_items else 0
    total_failures = sum(count for _, count in pareto_items)
    top_failure_pct = (top_failure_count / total_failures * 100) if total_failures > 0 else 0
    top_3_pct = (sum(count for _, count in pareto_items[:3]) / total_failures * 100) if total_failures > 0 else 0

    pareto_summary = (
        f"A total of {total_failures} failed tickets were recorded. The top failure contributor is "
        f"'{top_failure_code}', accounting for {top_failure_count} failures ({top_failure_pct:.1f}% of all failures). "
        f"The top 3 stock codes account for {top_3_pct:.1f}% of all defects. "
        f"Focus root-cause analysis on these leading contributors to achieve the greatest quality improvement."
    )

    max_failure_days = max((p["days"] for p in failure_points), default=0)
    mttf_summary = (
        f"The Mean Time To Failure (MTTF) for failed components is {mttf_days:.2f} days. "
        f"The longest a component survived before failing was {max_failure_days:.2f} days. "
        f"Components appearing below the dashed orange line are failing earlier than average, "
        f"which may indicate early-life infant mortality or specific stress-test failures."
    ) if mttf_days else "No failed tickets with valid start/completion times were found in this range."
# ==========================================================================================================























    return render_template(
        "admin_kpi.html",
        users=users,
        kpi_technicians=kpi_technicians,
        tech_id=tech_id,
        date_from=date_from_str,
        date_to=date_to_str,
        total_work=total_work,
        completed_work=completed_count,
        wip_work=wip_count,
        active_techs_count=len(active_techs),
        selected_tech_name=selected_tech_name,
        work_pie_chart=work_pie, overall_results_chart=overall_results_pie,
        tech_results_charts=tech_results_charts,
        ticket_rows=rows, kpi_stock_groups=kpi_stock_groups,
        kpi_ticket_details=kpi_ticket_details,
        response_stats=response_stats, response_buckets=response_buckets,
        chart_type=chart_type,
        
        # NEW:
        stacked_chart_html=stacked_chart_html,
        pareto_chart_html=pareto_chart_html,
        failure_scatter_html=failure_scatter_html,
        throughput_summary=throughput_summary,
        pareto_summary=pareto_summary,
        mttf_summary=mttf_summary,
        
        
        kpi_insights = generate_kpi_insights(
        total_work=total_work, completed_count=completed_count,
        wip_count=wip_count, active_techs_count=len(active_techs),
        result_counts=result_counts, tech_map=tech_map,
        response_stats=response_stats, response_buckets=response_buckets,
        buckets=buckets, bucket_labels=bucket_labels, stacked_series=stacked_series,
        pareto_items=pareto_items, failure_points=failure_points, mttf_days=mttf_days,
        date_from_str=date_from_str, date_to_str=date_to_str,
        )
        
        
        
    )












    # return render_template(
    #     "admin_kpi.html",
    #     users=users, kpi_technicians=kpi_technicians, tech_id=tech_id,
    #     date_from=date_from_str, date_to=date_to_str,
    #     total_work=total_work, completed_work=completed_count, wip_work=wip_count,
    #     active_techs_count=len(active_techs),
    #     selected_tech_name=selected_tech_name,
    #     work_pie_chart=work_pie, overall_results_chart=overall_results_pie,
    #     tech_results_charts=tech_results_charts,
    #     ticket_rows=rows, kpi_stock_groups=kpi_stock_groups,
    #     kpi_ticket_details=kpi_ticket_details,
    #     response_stats=response_stats, response_buckets=response_buckets,
    #     chart_type=chart_type)


@app.route("/admin/alerts")
@permission_required("alerts")
def admin_alerts():
    db = get_db(); today = datetime.date.today()

    def parse_date(value):
        value = (value or "").strip()
        for fmt in ("%Y-%m-%d","%Y/%m/%d","%m/%d/%Y"):
            try: return datetime.datetime.strptime(value, fmt).date()
            except ValueError: pass
        return None

    def parse_db_date(value):
        if value is None or not str(value).strip(): return None
        text = str(value).strip().replace("T"," ").replace("Z","")
        try:
            serial = float(text)
            if 1 <= serial <= 100000:
                return (datetime.datetime(1899,12,30) + datetime.timedelta(days=serial)).date()
        except (ValueError, TypeError, OverflowError): pass
        for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %I:%M %p","%Y/%m/%d %H:%M:%S","%Y/%m/%d",
                    "%Y-%m-%d %H:%M:%S.%f","%Y-%m-%d %H:%M:%S","%Y-%m-%d",
                    "%m/%d/%Y %I:%M:%S %p","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M:%S","%m/%d/%Y"):
            try: return datetime.datetime.strptime(text, fmt).date()
            except ValueError: pass
        try: return datetime.datetime.fromisoformat(text).date()
        except ValueError: return None
        
        
    def parse_db_datetime(value):
        if value is None: return None
        text = str(value).strip()
        if not text: return None
        try:
            serial = float(text)
            if 1 <= serial <= 100000:
                return datetime.datetime(1899,12,30) + datetime.timedelta(days=serial)
        except (ValueError, TypeError, OverflowError): pass
        clean = text.replace("T"," ").replace("Z","").strip()
        for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %I:%M %p","%Y/%m/%d %H:%M:%S","%Y/%m/%d %H:%M","%Y/%m/%d",
                    "%Y-%m-%d %I:%M:%S %p","%Y-%m-%d %I:%M %p","%Y-%m-%d %H:%M:%S.%f","%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d %H:%M","%Y-%m-%d","%m/%d/%Y %I:%M:%S %p","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M:%S",
                    "%m/%d/%Y %H:%M","%m/%d/%Y"):
            try: return datetime.datetime.strptime(clean, fmt)
            except ValueError: pass
        try: return datetime.datetime.fromisoformat(clean)
        except (ValueError, TypeError): return None
        
        
        
        
        
        
        
        
        
        

    selected = parse_date(request.args.get("week")) or today
    week_start = selected - datetime.timedelta(days=selected.weekday())
    week_end = week_start + datetime.timedelta(days=6)
    workweek_end = week_start + datetime.timedelta(days=4)
    windows = [("5 Work Days", week_start, workweek_end, 20),
               ("Trailing 2 Weeks", week_end - datetime.timedelta(days=13), week_end, 30),
               ("Trailing 3 Weeks", week_end - datetime.timedelta(days=20), week_end, 40),
               ("Trailing 1 Month", week_end - datetime.timedelta(days=29), week_end, 50)]
    earliest = min(item[1] for item in windows)
    db_rows = db.execute("""SELECT t.*, COALESCE(NULLIF(TRIM(t.technician_name),''), NULLIF(TRIM(u.username),'')) AS technician
        FROM tickets t LEFT JOIN users u ON u.id=t.assigned_to
        WHERE NULLIF(TRIM(t.stock_code),'') IS NOT NULL
        ORDER BY t.stock_code COLLATE NOCASE, t.id DESC""").fetchall()
    stock_map = {}; analyzed_stock_codes = set(); selected_week_ticket_count = 0; alert_ticket_details = {}
    for row in db_rows:
        event_date = (parse_db_date(row["completed_at"]) or parse_db_date(row["return_time"])
                      or parse_db_date(row["test_started_at"]) or parse_db_date(row["assigned_at"])
                      or parse_db_date(row["created_at"]) or parse_db_date(row["modified"]))
        if event_date is None or event_date < earliest or event_date > week_end: continue
        ticket = dict(row); ticket["alert_event_date"] = event_date
        stock = (ticket.get("stock_code") or "Uncategorized").strip() or "Uncategorized"
        stock_map.setdefault(stock, []).append(ticket)
        analyzed_stock_codes.add(stock)
        if week_start <= event_date <= week_end: selected_week_ticket_count += 1

    def category(ticket):
        raw = (ticket.get("test_result") or "").strip()
        folded = " ".join(raw.casefold().replace("-"," ").replace("_"," ").split())
        if folded == "ntf": return "NTF"
        if "failed" in folded or ("no post" in folded and "no log" in folded): return "Failed"
        if folded in {"not tested","not test","not run","untested","n/a","na"}: return "Not Tested"
        if not folded: return "Pending / WIP"
        return raw

    styles = {"NTF": ("#86efac","rgba(34,197,94,.50)","rgba(34,197,94,.06)","rgba(34,197,94,.18)","rgba(34,197,94,.035)"),
              "Failed": ("#fca5a5","rgba(239,68,68,.55)","rgba(239,68,68,.07)","rgba(239,68,68,.20)","rgba(239,68,68,.04)"),
              "Not Tested": ("#fcd34d","rgba(245,158,11,.50)","rgba(245,158,11,.06)","rgba(245,158,11,.18)","rgba(245,158,11,.035)"),
              "Pending / WIP": ("#93c5fd","rgba(79,140,255,.50)","rgba(79,140,255,.06)","rgba(79,140,255,.18)","rgba(79,140,255,.035)")}
    default_style = ("#c4b5fd","rgba(168,85,247,.50)","rgba(168,85,247,.06)","rgba(168,85,247,.18)","rgba(168,85,247,.035)")
    order = {"NTF":0,"Failed":1,"Not Tested":2,"Pending / WIP":99}

    alerts = []
    for stock, tickets in stock_map.items():
        metrics = []; triggered = False
        for label, start_date, end_date, threshold in windows:
            count = sum(1 for t in tickets if start_date <= t["alert_event_date"] <= end_date)
            hit = count >= threshold; triggered = triggered or hit
            metrics.append({"label": label, "start": start_date.strftime("%b %d, %Y"),
                            "end": end_date.strftime("%b %d, %Y"), "threshold": threshold,
                            "count": count, "triggered": hit})
        if not triggered: continue
        display_tickets = [t for t in tickets if earliest <= t["alert_event_date"] <= week_end]
        grouped = {}
        for ticket in display_tickets:
            grouped.setdefault(category(ticket), []).append(ticket)
            clean = dict(ticket); clean.pop("alert_event_date", None)
            alert_ticket_details[str(ticket["id"])] = clean
        result_groups = []
        for label in sorted(grouped, key=lambda value: (order.get(value,10), value.casefold())):
            color, border, background, badge, row = styles.get(label, default_style)
            result_groups.append({"label": label, "tickets": grouped[label], "color": color,
                                   "border": border, "background": background, "badge": badge, "row": row})
        alerts.append({"stock_code": stock, "metrics": metrics, "display_tickets": display_tickets,
                       "result_groups": result_groups, "ntf_count": len(grouped.get("NTF",[])),
                       "failed_count": len(grouped.get("Failed",[])),
                       "other_count": sum(len(v) for k, v in grouped.items() if k not in {"NTF","Failed"})})
    alerts.sort(key=lambda item: (-max(m["count"]/m["threshold"] for m in item["metrics"]), item["stock_code"].casefold()))
    return render_template("admin_alerts.html", alerts=alerts, selected_week=week_start.isoformat(),
                           week_label=week_start.strftime("%B %d, %Y"),
                           week_end_label=week_end.strftime("%B %d, %Y"),
                           analyzed_stock_count=len(analyzed_stock_codes),
                           selected_week_ticket_count=selected_week_ticket_count,
                           alert_ticket_details=alert_ticket_details)

















class AlertsPDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 16)
        self.cell(0, 8, "MRS Ticket Dashboard", 0, 1, "C")
        self.set_font("helvetica", "B", 12)
        self.cell(0, 6, "Volume Alerts & Product Serial Number Report", 0, 1, "C")
        self.set_font("helvetica", "", 9)
        self.cell(0, 5, f"Generated on: {now_standard()}", 0, 1, "C"); self.ln(6)
    def footer(self):
        self.set_y(-15); self.set_font("helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")


@app.route("/admin/alerts/pdf")
@admin_required
def admin_alerts_pdf():
    db = get_db(); now_dt = datetime.datetime.now()
    windows = [(5,20,"20+ within 5 days"),(14,30,"30+ within 2 weeks"),
               (21,40,"40+ within 3 weeks"),(30,50,"50+ within 1 month")]
    all_tickets = db.execute("""SELECT t.*, COALESCE(t.technician_name, u.username) AS technician
        FROM tickets t LEFT JOIN users u ON u.id = t.assigned_to
        ORDER BY t.stock_code, t.id""").fetchall()
    stock_map = {}
    for t in all_tickets:
        stock_map.setdefault(t["stock_code"], []).append(dict(t))
    triggered_alerts = []
    for sc, tickets in stock_map.items():
        for days_limit, min_count, label in windows:
            cutoff = now_dt - datetime.timedelta(days=days_limit); count_in_window = 0
            for t in tickets:
                ref_date_str = t["completed_at"] or t["assigned_at"] or t["created_at"]
                try:
                    clean_dt = ref_date_str.replace("/", "-")
                    dt = datetime.datetime.fromisoformat(clean_dt)
                    if dt >= cutoff: count_in_window += 1
                except Exception: count_in_window += 1
            if count_in_window >= min_count:
                triggered_alerts.append({"stock_code": sc, "threshold_label": label,
                                          "count": count_in_window, "tickets": tickets})
                break
    pdf = AlertsPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15); pdf.add_page()
    if not triggered_alerts:
        pdf.set_font("helvetica", "", 12)
        pdf.cell(0, 10, "No active volume alerts triggered at this time.", 0, 1, "L")
    else:
        for alert in triggered_alerts:
            pdf.set_font("helvetica", "B", 11); pdf.set_fill_color(240, 245, 255)
            pdf.cell(0, 7, f"Stock Code: {alert['stock_code']}  |  Threshold: {alert['threshold_label']}  |  Total Tickets: {alert['count']}", 1, 1, "L", fill=True)
            pdf.set_font("helvetica", "B", 9); pdf.set_fill_color(230, 235, 245)
            pdf.cell(35, 6, "MRS Ticket", 1, 0, "C", fill=True)
            pdf.cell(45, 6, "Serial Number", 1, 0, "C", fill=True)
            pdf.cell(25, 6, "Status", 1, 0, "C", fill=True)
            pdf.cell(25, 6, "Result", 1, 0, "C", fill=True)
            pdf.cell(60, 6, "Technician", 1, 1, "C", fill=True)
            pdf.set_font("helvetica", "", 9)
            for t in alert["tickets"]:
                pdf.cell(35, 5, str(t["mrs_ticket"]), 1, 0, "L")
                pdf.cell(45, 5, str(t["serial_number"] or "-"), 1, 0, "L")
                pdf.cell(25, 5, str(t["status"]), 1, 0, "C")
                pdf.cell(25, 5, str(t["test_result"] or "pending"), 1, 0, "C")
                pdf.cell(60, 5, str(t["technician"] or "Unassigned"), 1, 1, "L")
            pdf.ln(5)
    pdf_output = BytesIO(); pdf_output.write(pdf.output()); pdf_output.seek(0)
    filename = f"mrs_volume_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(pdf_output, mimetype="application/pdf", as_attachment=True, download_name=filename)


HISTORY_DB_PATH = os.path.join(os.path.dirname(DB_PATH), "mrs_history_completed.db")
HISTORY_EXPORT_FIELDS = [
    ("Title","mrs_ticket"),("Part SN","serial_number"),("WH Location","wh_location"),
    ("Technician","technician_name"),("Stock Code","stock_code"),("Part Type","part_type"),
    ("Part Description","part_description"),("Assigned Time","assigned_at"),
    ("Test Start Time","test_started_at"),("Test End Time","completed_at"),("Return Time","return_time"),
    ("Result","test_result"),("Test Failure","failure_reason"),("Quality Disposition","quality_disposition"),
    ("Logs Uploaded","logs_uploaded"),("Log Path","log_path"),("Comments","mrs_comments"),
    ("Stock_cd","stock_cd"),("BB Flag","bb_flag"),("SXM1 Flag","sxm1_flag"),("SXM2 Flag","sxm2_flag"),
    ("SXM3 Flag","sxm3_flag"),("SXM4 Flag","sxm4_flag"),("SXM5 Flag","sxm5_flag"),
    ("SXM6 Flag","sxm6_flag"),("SXM7 Flag","sxm7_flag"),("SXM8 Flag","sxm8_flag"),
    ("ID","csv_id"),("Index","csv_index"),("Modified","modified")]

def _sync_history_database(source_db):
    h=sqlite3.connect(HISTORY_DB_PATH); h.row_factory=sqlite3.Row
    h.execute("CREATE TABLE IF NOT EXISTS completed_tickets (ticket_id INTEGER PRIMARY KEY, payload TEXT NOT NULL, modified TEXT)")
    h.execute("CREATE TABLE IF NOT EXISTS field_options (id INTEGER PRIMARY KEY AUTOINCREMENT, field_name TEXT NOT NULL, option_value TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0, UNIQUE(field_name, option_value))")
    preset_options = {
        "Logs Uploaded": ["TRUE", "FALSE"],
        "Quality Disposition": ["N/A"],
        "BB Flag": ["TRUE", "FALSE"],
        "SXM1 Flag": ["TRUE", "FALSE"],
        "SXM2 Flag": ["TRUE", "FALSE"],
        "SXM3 Flag": ["TRUE", "FALSE"],
        "SXM4 Flag": ["TRUE", "FALSE"],
        "SXM5 Flag": ["TRUE", "FALSE"],
        "SXM6 Flag": ["TRUE", "FALSE"],
        "SXM7 Flag": ["TRUE", "FALSE"],
        "SXM8 Flag": ["TRUE", "FALSE"],
    }
    for field_name, option_values in preset_options.items():
        for sort_order, option_value in enumerate(option_values):
            h.execute("INSERT OR IGNORE INTO field_options(field_name, option_value, sort_order) VALUES(?,?,?)",
                      (field_name, option_value, sort_order))
    rows=source_db.execute("SELECT * FROM tickets WHERE status='completed'").fetchall()
    for r in rows:
        h.execute("INSERT OR REPLACE INTO completed_tickets(ticket_id,payload,modified) VALUES(?,?,?)",(r['id'],json.dumps(dict(r),default=str),r['modified'] or r['completed_at']))
    h.commit(); h.close()

def _history_options():
    h=sqlite3.connect(HISTORY_DB_PATH); h.row_factory=sqlite3.Row
    h.execute("CREATE TABLE IF NOT EXISTS field_options (id INTEGER PRIMARY KEY AUTOINCREMENT, field_name TEXT NOT NULL, option_value TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0, UNIQUE(field_name, option_value))")
    preset_options = {"Logs Uploaded": ["TRUE", "FALSE"], "Quality Disposition": ["N/A"],
                      "BB Flag": ["TRUE", "FALSE"], **{f"SXM{i} Flag": ["TRUE", "FALSE"] for i in range(1, 9)}}
    for field_name, option_values in preset_options.items():
        for sort_order, option_value in enumerate(option_values):
            h.execute("INSERT OR IGNORE INTO field_options(field_name, option_value, sort_order) VALUES(?,?,?)",
                      (field_name, option_value, sort_order))
    h.commit()
    rows=h.execute("SELECT * FROM field_options ORDER BY field_name,sort_order,option_value COLLATE NOCASE").fetchall(); h.close(); return rows

@app.route('/admin/history-database-builder', methods=['GET','POST'])
@admin_required
def history_database_builder():
    _sync_history_database(get_db())
    if request.method=='POST':
        field = (request.form.get('field_name') or '').strip()
        raw_values = (request.form.get('option_value') or '').strip()
        valid = {x[0] for x in HISTORY_EXPORT_FIELDS}
        # Split comma-separated input, trim whitespace, discard empty entries,
        # and remove duplicates from the submitted batch while preserving order.
        choices = []
        seen = set()
        for item in raw_values.split(','):
            choice = item.strip()
            key = choice.casefold()
            if choice and key not in seen:
                choices.append(choice)
                seen.add(key)
        if field not in valid or not choices:
            flash('Select a title and enter at least one choice.', 'error')
        else:
            h = sqlite3.connect(HISTORY_DB_PATH)
            added = 0
            skipped = 0
            try:
                for choice in choices:
                    try:
                        h.execute("INSERT INTO field_options(field_name,option_value) VALUES(?,?)", (field, choice))
                        added += 1
                    except sqlite3.IntegrityError:
                        skipped += 1
                h.commit()
                if added and skipped:
                    flash(f'{added} choices added; {skipped} duplicate choices skipped.', 'success')
                elif added:
                    flash(f"{added} choice{'s' if added != 1 else ''} added.", 'success')
                else:
                    flash('All submitted choices already exist.', 'error')
            finally:
                h.close()
        return redirect(url_for('history_database_builder'))
    return render_template('history_database_builder.html',fields=[x[0] for x in HISTORY_EXPORT_FIELDS],options=_history_options(),db_path=HISTORY_DB_PATH)

@app.post('/admin/history-database-builder/edit/<int:option_id>')
@admin_required
def history_database_option_edit(option_id):
    value=(request.form.get('option_value') or '').strip()
    if value:
        h=sqlite3.connect(HISTORY_DB_PATH)
        try: h.execute('UPDATE field_options SET option_value=? WHERE id=?',(value,option_id)); h.commit(); flash('Choice updated.','success')
        except sqlite3.IntegrityError: flash('That choice already exists.','error')
        finally: h.close()
    return redirect(url_for('history_database_builder'))

@app.post('/admin/history-database-builder/delete/<int:option_id>')
@admin_required
def history_database_option_delete(option_id):
    h=sqlite3.connect(HISTORY_DB_PATH); h.execute('DELETE FROM field_options WHERE id=?',(option_id,)); h.commit(); h.close(); flash('Choice removed.','success'); return redirect(url_for('history_database_builder'))

def _history_option_map():
    result = {title: [] for title, key in HISTORY_EXPORT_FIELDS}
    for row in _history_options():
        result.setdefault(row["field_name"], []).append(row["option_value"])
    return result

def _history_filter(db):
    is_admin = bool(session.get("is_admin")); today = datetime.date.today()
    raw_from = (request.args.get("from") or "").strip().replace("-", "/")
    raw_to = (request.args.get("to") or "").strip().replace("-", "/")
    try: date_from = datetime.datetime.strptime(raw_from, "%Y/%m/%d").date() if raw_from else today - datetime.timedelta(days=7)
    except ValueError: date_from = today - datetime.timedelta(days=7)
    try: date_to = datetime.datetime.strptime(raw_to, "%Y/%m/%d").date() if raw_to else today
    except ValueError: date_to = today
    tech_id = (request.args.get("tech") or "").strip()
    q = (request.args.get("q") or "").strip()
    f_stock = (request.args.get("f_stock") or "").strip()
    f_tech = (request.args.get("f_tech") or "").strip()
    f_result = (request.args.get("f_result") or "").strip()
    f_part_type = (request.args.get("f_part_type") or "").strip()
    f_wh = (request.args.get("f_wh") or "").strip()
    f_qd = (request.args.get("f_qd") or "").strip()
    sql = """SELECT t.*, COALESCE(t.technician_name, u.username) AS technician
        FROM tickets t LEFT JOIN users u ON u.id = t.assigned_to
        WHERE t.status = 'completed' AND t.completed_at IS NOT NULL"""
    params = []
    if not is_admin:
        sql += " AND t.assigned_to = ?"; params.append(session["user_id"])
    elif tech_id:
        try: sql += " AND t.assigned_to = ?"; params.append(int(tech_id))
        except ValueError: pass
    if q:
        sql += " AND (t.stock_code LIKE ? OR t.mrs_ticket LIKE ? OR t.serial_number LIKE ? OR t.mrs_comments LIKE ? OR t.failure_reason LIKE ? OR t.part_description LIKE ?)"
        params += [f"%{q}%"]*6
    sql += " ORDER BY t.completed_at DESC"
    all_completed = db.execute(sql, params).fetchall()

    filtered_rows = []
    for r in all_completed:
        comp_str = r["completed_at"]; dt = None
        if comp_str:
            for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %H:%M:%S","%Y-%m-%d %H:%M:%S","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M","%Y-%m-%d"):
                try: dt = datetime.datetime.strptime(comp_str.strip(), fmt).date(); break
                except ValueError: continue
        if dt and not (date_from <= dt <= date_to): continue
        match = True
        if f_stock:
            sc_val = (r["stock_code"] or "")
            if f_stock.lower() == "[empty]":
                if sc_val.strip() != "": match = False
            elif f_stock.lower() not in sc_val.lower(): match = False
        if match and f_tech:
            tech_val = (r["technician"] or "")
            if f_tech.lower() == "[empty]":
                if tech_val.strip() != "": match = False
            elif f_tech.lower() not in tech_val.lower(): match = False
        if match and f_result:
            res_val = (r["test_result"] or "")
            if f_result == "__EMPTY__":
                if res_val.strip() != "": match = False
            elif f_result == "__FAIL_OR_NTF__":
                if res_val.lower() not in ("failed","not_tested"): match = False
            elif f_result.lower() != res_val.lower(): match = False
        if match and f_part_type:
            pt_val = (r["part_type"] or "")
            if f_part_type.lower() == "[empty]":
                if pt_val.strip() != "": match = False
            elif f_part_type.lower() not in pt_val.lower(): match = False
        if match and f_wh:
            wh_val = (r["wh_location"] or "")
            if f_wh.lower() == "[empty]":
                if wh_val.strip() != "": match = False
            elif f_wh.lower() not in wh_val.lower(): match = False
        if match and f_qd:
            qd_val = (r["quality_disposition"] or "")
            if f_qd.lower() == "[empty]":
                if qd_val.strip() != "": match = False
            elif f_qd.lower() not in qd_val.lower(): match = False
        if match: filtered_rows.append(r)
    return {"rows": filtered_rows, "date_from": date_from.strftime("%Y/%m/%d"),
            "date_to": date_to.strftime("%Y/%m/%d"), "tech_id": tech_id, "q": q,
            "f_stock": f_stock, "f_tech": f_tech, "f_result": f_result,
            "f_part_type": f_part_type, "f_wh": f_wh, "f_qd": f_qd, "is_admin": is_admin}


def _format_standard_time(ts_str):
    if not ts_str: return "-"
    try:
        for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %H:%M:%S","%Y-%m-%d %H:%M:%S","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M"):
            try:
                dt = datetime.datetime.strptime(ts_str.strip(), fmt)
                return dt.strftime("%Y/%m/%d %I:%M:%S %p")
            except ValueError: continue
        return ts_str
    except Exception: return ts_str


def _turnaround(assigned_at, test_started, completed):
    if not assigned_at or not completed: return "-"
    try:
        start_time_str = test_started if test_started else assigned_at
        for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %H:%M:%S","%Y-%m-%d %H:%M:%S","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M"):
            try: a = datetime.datetime.strptime(start_time_str.strip(), fmt); break
            except ValueError: continue
        else: return "-"
        for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %H:%M:%S","%Y-%m-%d %H:%M:%S","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M"):
            try: b = datetime.datetime.strptime(completed.strip(), fmt); break
            except ValueError: continue
        else: return "-"
        secs = int((b - a).total_seconds())
        if secs < 0: return "-"
        if secs < 60: return f"{secs}s"
        if secs < 3600: return f"{secs // 60}m {secs % 60}s"
        if secs < 86400: return f"{secs // 3600}h {(secs % 3600) // 60}m"
        return f"{secs // 86400}d {(secs % 86400) // 3600}h"
    except Exception: return "-"


@app.route("/history")
@permission_required("history")
def history():
    db = get_db(); _sync_history_database(db); f = _history_filter(db); rows = f["rows"]
    stock_groups = {}
    for r in rows:
        sc = r["stock_code"]
        if sc not in stock_groups: stock_groups[sc] = {"stock_code": sc, "tickets": []}
        d = dict(r)
        d["created_at"] = _format_standard_time(r["created_at"])
        d["assigned_at"] = _format_standard_time(r["assigned_at"])
        d["test_started_at"] = _format_standard_time(r["test_started_at"])
        d["completed_at"] = _format_standard_time(r["completed_at"])
        d["return_time"] = _format_standard_time(r["return_time"])
        d["turnaround"] = _turnaround(r["assigned_at"], r["test_started_at"], r["completed_at"])
        if (d.get("test_result") or "").strip().casefold() == "ntf": d["failure_reason"] = ""
        stock_groups[sc]["tickets"].append(d)
    grouped_tickets = list(stock_groups.values())
    techs_set = {r["technician"] for r in rows if r["technician"]}
    stocks_set = {r["stock_code"] for r in rows}
    tech_pie = None
    if f["is_admin"] and rows:
        counts = {}
        for r in rows:
            n = r["technician"] or "unassigned"; counts[n] = counts.get(n, 0) + 1
        top = sorted(counts.items(), key=lambda kv: -kv[1])[:8]
        palette = ["#4f8cff","#22c55e","#f59e0b","#a855f7","#06b6d4","#ef4444","#eab308","#ec4899"]
        data = [(n, c, palette[i % len(palette)]) for i, (n, c) in enumerate(top)]
        tech_pie = Markup(pie_chart(data, size=160, title="Completed by technician"))
    users = []
    if f["is_admin"]:
        users = db.execute("SELECT id, username FROM users ORDER BY username COLLATE NOCASE").fetchall()
    return render_template("history.html",
        date_from=f["date_from"], date_to=f["date_to"], tech_id=f["tech_id"], q=f["q"],
        f_stock=f["f_stock"], f_tech=f["f_tech"], f_result=f["f_result"],
        f_part_type=f["f_part_type"], f_wh=f["f_wh"], f_qd=f["f_qd"],
        is_admin=f["is_admin"], grouped_tickets=grouped_tickets,
        total=len(rows), techs_count=len(techs_set), stocks_count=len(stocks_set),
        tech_pie=tech_pie, users=users)


@app.route("/history/export.csv")
@permission_required("history")
def history_export():
    db=get_db(); _sync_history_database(db); f=_history_filter(db); buf=StringIO(); w=csv.writer(buf)
    w.writerow([title for title, key in HISTORY_EXPORT_FIELDS])
    for r in f["rows"]:
        values=[]
        for title,key in HISTORY_EXPORT_FIELDS:
            value=r[key] if key in r.keys() else ""
            values.append("" if value is None else value)
        w.writerow(values)
    filename=f"mrs_history_{f['date_from'].replace('/', '-')}_to_{f['date_to'].replace('/', '-')}.csv"
    return Response(buf.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename={filename}"})


@app.post("/admin/history/delete-all")
@admin_required
def history_delete_all():
    db = get_db()
    db.execute("DELETE FROM tickets WHERE status='completed'"); db.commit()
    flash("All completed history entries have been deleted.", "success")
    return redirect(url_for("history"))


@app.post("/admin/history/import-csv")
@admin_required
def history_import_csv():
    if "csv_file" not in request.files:
        flash("No file part in request.", "error"); return redirect(url_for("history"))
    file = request.files["csv_file"]
    if file.filename == "": flash("No selected file.", "error"); return redirect(url_for("history"))
    db = get_db(); added = 0; skipped = 0
    try:
        stream = io.TextIOWrapper(file.stream, encoding="utf-8-sig")
        reader = csv.DictReader(stream)
        for row in reader:
            stock_code = (row.get("Stock Code") or row.get("stock_code") or "STK-UNKNOWN").strip()
            mrs_ticket = (row.get("Title") or row.get("mrs_ticket") or row.get("MRS Ticket") or "").strip()
            if not mrs_ticket: skipped += 1; continue
            serial_number = (row.get("Part SN") or row.get("serial_number") or "").strip()
            wh_location = (row.get("WH Location") or "").strip()
            technician_name = (row.get("Technician") or "").strip()
            part_type = (row.get("Part Type") or "").strip()
            part_description = (row.get("Part Description") or "").strip()
            assigned_at = (row.get("Assigned Time") or "").strip()
            test_started_at = (row.get("Test Start Time") or "").strip()
            completed_at = (row.get("Test End Time") or row.get("Return Time") or "").strip()
            return_time = (row.get("Return Time") or "").strip()
            test_result = (row.get("Result") or "").strip()
            failure_reason = (row.get("Test Failure") or row.get("failure_reason") or "").strip()
            quality_disposition = (row.get("Quality Disposition") or "").strip()
            logs_uploaded = (row.get("Logs Uploaded") or "").strip()
            log_path = (row.get("Log Path") or "").strip()
            mrs_comments = (row.get("Comments") or row.get("mrs_comments") or "").strip()
            db.execute("""INSERT INTO tickets (stock_code, mrs_ticket, serial_number, mrs_comments,
                status, assigned_at, completed_at, created_at, technician_name,
                test_started_at, test_result, failure_reason, wh_location,
                part_type, part_description, return_time, quality_disposition,
                logs_uploaded, log_path) VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (stock_code, mrs_ticket, serial_number, mrs_comments,
                 assigned_at or now_standard(), completed_at or now_standard(),
                 assigned_at or now_standard(), technician_name, test_started_at,
                 test_result, failure_reason, wh_location, part_type, part_description,
                 return_time, quality_disposition, logs_uploaded, log_path))
            added += 1
        db.commit()
        flash(f"Successfully imported {added} history records ({skipped} skipped).", "success")
    except Exception as exc:
        flash(f"Error importing CSV: {exc}", "error")
    return redirect(url_for("history"))


def _ticket_or_404(db, tid):
    row = db.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    if row is None: abort(404)
    return row


@app.post("/stock/<path:stock_code>/assign")
@login_required
def assign_stock(stock_code):
    db = get_db()
    t_list = db.execute("SELECT * FROM tickets WHERE stock_code = ? AND status='available'", (stock_code,)).fetchall()
    if not t_list:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "message": "No available tickets for this stock code or already claimed."})
        flash("No available tickets for this stock code or already claimed.", "error")
        return redirect(url_for("overview"))
    cur = db.execute("UPDATE tickets SET status='assigned', assigned_to=?, assigned_at=?, "
                     "completed_at=NULL, transfer_count=0 WHERE stock_code=? AND status='available'",
                     (session["user_id"], now_standard(), stock_code))
    db.commit()
    if cur.rowcount:
        mrs_list = ", ".join([t["mrs_ticket"] for t in t_list])
        msg = f"Stock code {stock_code} claimed ({mrs_list}). You are the technician."
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": True, "message": msg})
        flash(msg, "success")
        return redirect(url_for("overview"))
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": False, "message": "Someone else grabbed it first."})
    flash("Someone else grabbed it first.", "error")
    return redirect(url_for("overview"))


@app.post("/ticket/<int:tid>/start-test-ajax")
@login_required
def start_test_ajax(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    if t["assigned_to"] != session["user_id"] and not session.get("is_admin"):
        return jsonify({"success": False, "message": "Not your ticket."}), 403
    if t["status"] != "assigned":
        return jsonify({"success": False, "message": "Ticket not in assigned status."}), 400
    t_time = now_standard()
    db.execute("UPDATE tickets SET test_started_at=? WHERE id=?", (t_time, tid))
    db.commit()
    return jsonify({"success": True, "test_started_at": t_time})


@app.post("/ticket/<int:tid>/complete-pass-ajax")
@login_required
def complete_pass_ajax(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    if t["assigned_to"] != session["user_id"] and not session.get("is_admin"):
        return jsonify({"success": False, "message": "Not your ticket."}), 403
    if t["status"] != "assigned":
        return jsonify({"success": False, "message": "Ticket not in assigned status."}), 400
    def text(name, default=""):
        return (request.form.get(name) or default).strip()
    logs_uploaded = text("logs_uploaded", "no").lower()
    log_path = text("log_path")
    if logs_uploaded not in {"yes", "no"}:
        return jsonify({"success": False, "message": "Select Yes or No for Logs Uploaded."}), 400
    if logs_uploaded == "yes" and not log_path:
        return jsonify({"success": False, "message": "Log Path is required when logs are uploaded."}), 400
    if logs_uploaded == "no": log_path = "no Log"
    required = {"mrs_ticket":"Title", "serial_number":"Part SN", "wh_location":"WH Location",
                "technician_name":"Technician", "stock_code":"Stock Code", "test_result":"Result"}
    for key, label in required.items():
        if not text(key): return jsonify({"success": False, "message": f"{label} is required."}), 400
    flag_names = ["bb_flag"] + [f"sxm{i}_flag" for i in range(1,9)]
    flags = []
    for name in flag_names:
        raw = text(name, "0").lower()
        flags.append(1 if raw in {"1","yes","true","on"} else 0)
    values = (
        text("mrs_ticket"), text("serial_number"), text("wh_location"), text("technician_name"),
        text("stock_code"), text("part_type"), text("part_description"), text("assigned_at"),
        text("test_started_at"), text("completed_at", now_standard()), text("return_time"),
        text("test_result", "NTF"), text("failure_reason"), text("quality_disposition"),
        logs_uploaded, log_path, text("mrs_comments"), text("stock_cd"), *flags,
        text("csv_id") or None, text("csv_index"), text("modified", now_standard()), tid)
    db.execute("""UPDATE tickets SET status='completed', mrs_ticket=?, serial_number=?, wh_location=?,
        technician_name=?, stock_code=?, part_type=?, part_description=?, assigned_at=?,
        test_started_at=?, completed_at=?, return_time=?, test_result=?, failure_reason=?,
        quality_disposition=?, logs_uploaded=?, log_path=?, mrs_comments=?, stock_cd=?,
        bb_flag=?, sxm1_flag=?, sxm2_flag=?, sxm3_flag=?, sxm4_flag=?, sxm5_flag=?,
        sxm6_flag=?, sxm7_flag=?, sxm8_flag=?, csv_id=?, csv_index=?, modified=? WHERE id=?""", values)
    db.commit()
    _sync_history_database(db)
    return jsonify({"success": True})


@app.get("/ticket/<int:tid>/print-label")
@login_required
def print_ticket_label(tid):
    db = get_db()
    ticket = db.execute("""SELECT t.*, u.username AS assigned_username
        FROM tickets t LEFT JOIN users u ON u.id=t.assigned_to WHERE t.id=?""", (tid,)).fetchone()
    if not ticket:
        abort(404)
    if ticket["assigned_to"] != session["user_id"] and not session.get("is_admin"):
        abort(403)
    return render_template("ticket_label.html", t=ticket)


@app.post("/ticket/<int:tid>/complete-fail-ajax")
@login_required
def complete_fail_ajax(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    reason = (request.form.get("failure_reason") or "").strip()
    if t["assigned_to"] != session["user_id"] and not session.get("is_admin"):
        return jsonify({"success": False, "message": "Not your ticket."}), 403
    if t["status"] != "assigned":
        return jsonify({"success": False, "message": "Ticket not in assigned status."}), 400
    if not reason:
        return jsonify({"success": False, "message": "Failure reason is required."}), 400
    db.execute("UPDATE tickets SET status='completed', completed_at=?, test_result='failed', "
               "failure_reason=?, technician_name=? WHERE id=?",
               (now_standard(), reason, session["username"], tid))
    db.commit()
    return jsonify({"success": True})


@app.post("/ticket/<int:tid>/complete-not-tested-ajax")
@login_required
def complete_not_tested_ajax(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    reason = (request.form.get("not_tested_reason") or "").strip()
    if t["assigned_to"] != session["user_id"] and not session.get("is_admin"):
        return jsonify({"success": False, "message": "Not your ticket."}), 403
    if t["status"] != "assigned":
        return jsonify({"success": False, "message": "Ticket not in assigned status."}), 400
    if not reason:
        return jsonify({"success": False, "message": "Reason is required."}), 400
    db.execute("UPDATE tickets SET status='completed', completed_at=?, test_result='not_tested', "
               "failure_reason=?, technician_name=? WHERE id=?",
               (now_standard(), reason, session["username"], tid))
    db.commit()
    return jsonify({"success": True})


@app.post("/ticket/<int:tid>/release-ajax")
@login_required
def release_ticket_ajax(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    if t["assigned_to"] != session["user_id"] and not session.get("is_admin"):
        return jsonify({"success": False, "message": "Not authorized."}), 403
    if t["status"] != "assigned":
        return jsonify({"success": False, "message": "Ticket not in assigned status."}), 400
    db.execute("UPDATE tickets SET status='available', assigned_to=NULL, assigned_at=NULL, "
               "completed_at=NULL, test_started_at=NULL, test_result=NULL, failure_reason=NULL WHERE id=?", (tid,))
    db.commit()
    return jsonify({"success": True})


@app.post("/ticket/<int:tid>/transfer-ajax")
@login_required
def transfer_ticket_ajax(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    if t["assigned_to"] != session["user_id"] and not session.get("is_admin"):
        return jsonify({"success": False, "message": "Not authorized."}), 403
    if t["status"] != "assigned":
        return jsonify({"success": False, "message": "Ticket not in assigned status."}), 400
    target_uid = request.form.get("target_user_id")
    if not target_uid:
        return jsonify({"success": False, "message": "Target technician required."}), 400
    target_user = db.execute("SELECT id, username FROM users WHERE id=?", (target_uid,)).fetchone()
    if not target_user:
        return jsonify({"success": False, "message": "Target technician not found."}), 404
    db.execute("UPDATE tickets SET assigned_to=?, assigned_at=?, transfer_count=COALESCE(transfer_count,0)+1 WHERE id=?",
               (target_user["id"], now_standard(), tid))
    db.commit()
    return jsonify({"success": True, "message": f"Ticket {t['mrs_ticket']} successfully transferred to {target_user['username']}."})


@app.post("/ticket/<int:tid>/add-note-ajax")
@login_required
def add_note_ajax(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    if t["assigned_to"] != session["user_id"] and not session.get("is_admin"):
        return jsonify({"success": False, "message": "Not authorized."}), 403
    note = (request.form.get("note") or "").strip()
    if not note:
        return jsonify({"success": False, "message": "Note text is required."}), 400
    timestamp = now_standard()
    existing_comments = (t["mrs_comments"] or "").strip()
    formatted_note = f"[{timestamp} - Note by {session['username']}]: {note}"
    updated_comments = f"{existing_comments}\n{formatted_note}" if existing_comments else formatted_note
    db.execute("UPDATE tickets SET mrs_comments=? WHERE id=?", (updated_comments, tid))
    db.commit()
    return jsonify({"success": True, "updated_comments": updated_comments, "message": "Note saved successfully!"})


@app.post("/ticket/<int:tid>/delete-ajax")
@admin_required
def delete_ticket_ajax(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    db.execute("DELETE FROM tickets WHERE id=?", (tid,)); db.commit()
    return jsonify({"success": True, "message": f"Ticket {t['mrs_ticket']} deleted."})


@app.post("/ticket/<int:tid>/reopen")
@login_required
def reopen_ticket(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    if t["assigned_to"] != session["user_id"] and not session.get("is_admin"):
        flash("Not authorized.", "error")
    elif t["status"] != "completed":
        flash("Only completed tickets can be reopened.", "error")
    else:
        db.execute("UPDATE tickets SET status='assigned', completed_at=NULL, test_result=NULL, failure_reason=NULL WHERE id=?", (tid,))
        db.commit()
        flash(f"Ticket {t['mrs_ticket']} reopened.", "success")
    return redirect(url_for("my_completed"))


@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    raw_users = db.execute("""SELECT u.*,
        (SELECT COUNT(*) FROM tickets WHERE assigned_to=u.id AND status='assigned') AS open_count,
        (SELECT COUNT(*) FROM tickets WHERE assigned_to=u.id AND status='completed') AS done_count,
        (SELECT COUNT(*) FROM yubikey_otp_credentials WHERE user_id=u.id) AS yubikey_count
        FROM users u ORDER BY u.username COLLATE NOCASE""").fetchall()
    users = []
    for row in raw_users:
        item = dict(row)
        item["allowed_tabs"] = {r["tab_key"] for r in db.execute("SELECT tab_key FROM user_permissions WHERE user_id=? AND allowed=1", (row["id"],)).fetchall()}
        item["allowed_sections"] = {r["section_key"] for r in db.execute("SELECT section_key FROM section_permissions WHERE user_id=? AND allowed=1", (row["id"],)).fetchall()}
        item["allowed_te_tabs"] = {r["tab_key"] for r in db.execute("SELECT tab_key FROM te_permissions WHERE user_id=? AND allowed=1", (row["id"],)).fetchall()}
        item["can_edit_work_instructions"] = bool(db.execute("SELECT allowed FROM work_instruction_editors WHERE user_id=? AND allowed=1", (row["id"],)).fetchone())
        item["yubikeys"] = [dict(k) for k in db.execute("SELECT public_id, device_name, created_at, last_used_at FROM yubikey_otp_credentials WHERE user_id=? ORDER BY id", (row["id"],)).fetchall()]
        users.append(item)
    yubico_client_id, yubico_secret_key = _load_yubico_config()
    return render_template("admin_users.html", users=users, permission_tabs=TAB_PERMISSIONS,
                           section_permissions=SECTION_LABELS, te_permission_tabs=TE_TAB_PERMISSIONS,
                           yubico_configured=bool(yubico_client_id and yubico_secret_key),
                           yubico_client_id=yubico_client_id, yubico_hmac_ok=_yubico_hmac_self_test())


@app.post("/admin/users/add")
@admin_required
def admin_users_add():
    username = (request.form.get("username") or "").strip()
    is_admin = 1 if request.form.get("is_admin") else 0
    if not username:
        flash("Username is required.", "error")
    else:
        db = get_db(); disabled_password = secrets.token_urlsafe(64)
        try:
            cur = db.execute("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
                             (username, generate_password_hash(disabled_password), is_admin, now_standard()))
            db.execute("INSERT OR IGNORE INTO section_permissions(user_id,section_key,allowed) VALUES(?,?,1)", (cur.lastrowid, "osv"))
            db.commit()
            flash(f"User '{username}' created. Register a YubiKey OTP for this account before signing out.", "success")
        except sqlite3.IntegrityError:
            flash(f"Username '{username}' already exists.", "error")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:uid>/reset")
@admin_required
def admin_users_reset(uid):
    flash("Password authentication is disabled. Register or replace the user's YubiKey OTP instead.", "error")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:uid>/delete")
@admin_required
def admin_users_delete(uid):
    db = get_db(); user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if user is None: abort(404)
    if uid == session["user_id"]:
        flash("You cannot delete yourself.", "error"); return redirect(url_for("admin_users"))
    if user["is_admin"]:
        admins = db.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0]
        if admins <= 1:
            flash("Cannot delete the last admin.", "error"); return redirect(url_for("admin_users"))
    db.execute("UPDATE tickets SET technician_name = COALESCE(technician_name, ?) WHERE assigned_to = ? AND status = 'completed'",
               (user["username"], uid))
    db.execute("UPDATE tickets SET status='available', assigned_to=NULL, assigned_at=NULL, completed_at=NULL, "
               "test_started_at=NULL, test_result=NULL, failure_reason=NULL WHERE assigned_to=? AND status != 'completed'", (uid,))
    db.execute("DELETE FROM users WHERE id=?", (uid,)); db.commit()
    flash(f"User '{user['username']}' deleted. Completed tickets kept in history.", "success")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:uid>/categorized-access")
@admin_required
def admin_user_categorized_access(uid):
    db = get_db(); user = db.execute("SELECT id,is_admin FROM users WHERE id=?", (uid,)).fetchone()
    if not user: abort(404)
    if user["is_admin"]:
        flash("Administrators always have full OSV and TE access.", "error"); return redirect(url_for("admin_users"))
    osv_selected = set(request.form.getlist("osv_tab")) & set(TAB_PERMISSIONS)
    te_selected = set(request.form.getlist("te_tab")) & set(TE_TAB_PERMISSIONS)
    db.execute("DELETE FROM user_permissions WHERE user_id=?", (uid,))
    db.executemany("INSERT INTO user_permissions(user_id,tab_key,allowed) VALUES(?,?,1)", [(uid, key) for key in osv_selected])
    db.execute("DELETE FROM te_permissions WHERE user_id=?", (uid,))
    db.executemany("INSERT INTO te_permissions(user_id,tab_key,allowed) VALUES(?,?,1)", [(uid, key) for key in te_selected])
    db.execute("DELETE FROM section_permissions WHERE user_id=?", (uid,))
    sections = []
    if osv_selected: sections.append((uid, "osv"))
    if te_selected: sections.append((uid, "te"))
    db.executemany("INSERT INTO section_permissions(user_id,section_key,allowed) VALUES(?,?,1)", sections)
    can_edit_wi = 1 if request.form.get("can_edit_work_instructions") == "1" else 0
    db.execute("INSERT INTO work_instruction_editors(user_id,allowed) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET allowed=excluded.allowed", (uid, can_edit_wi))
    db.commit()
    flash("OSV and TE access updated.", "success")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:uid>/permissions")
@admin_required
def admin_user_permissions(uid):
    db = get_db(); user = db.execute("SELECT id,is_admin FROM users WHERE id=?", (uid,)).fetchone()
    if not user: abort(404)
    if user["is_admin"]:
        flash("Administrators always have full access.", "error"); return redirect(url_for("admin_users"))
    selected = set(request.form.getlist("tab")) & set(TAB_PERMISSIONS)
    db.execute("DELETE FROM user_permissions WHERE user_id=?", (uid,))
    db.executemany("INSERT INTO user_permissions(user_id,tab_key,allowed) VALUES(?,?,1)", [(uid, key) for key in selected])
    db.commit(); flash("User tab access updated.", "success")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:uid>/sections")
@admin_required
def admin_user_sections(uid):
    db = get_db(); user = db.execute("SELECT id,is_admin FROM users WHERE id=?", (uid,)).fetchone()
    if not user: abort(404)
    if user["is_admin"]:
        flash("Administrators always have access to OSV and Test Engineering.", "error"); return redirect(url_for("admin_users"))
    selected = set(request.form.getlist("section")) & set(SECTION_LABELS)
    db.execute("DELETE FROM section_permissions WHERE user_id=?", (uid,))
    db.executemany("INSERT INTO section_permissions(user_id,section_key,allowed) VALUES(?,?,1)", [(uid, key) for key in selected])
    db.commit(); flash("User section access updated.", "success")
    return redirect(url_for("admin_users"))


@app.post("/admin/yubico-config")
@admin_required
def admin_yubico_config():
    client_id = (request.form.get("client_id") or "").strip()
    secret_key = _normalize_yubico_secret(request.form.get("secret_key"))
    if not client_id.isdigit():
        flash("Yubico Client ID must contain numbers only.", "error"); return redirect(url_for("admin_users"))
    try:
        _decode_yubico_secret(secret_key)
    except Exception:
        flash("Yubico Secret Key must be the Base64 secret supplied by Yubico.", "error")
        return redirect(url_for("admin_users"))
    try:
        _save_yubico_config(client_id, secret_key)
    except OSError as exc:
        flash(f"Could not save YubiCloud settings: {exc}", "error"); return redirect(url_for("admin_users"))
    flash("YubiCloud validation settings saved.", "success")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:uid>/yubikey-otp/register")
@admin_required
def admin_user_yubikey_otp_register(uid):
    db = get_db(); user = db.execute("SELECT id,username FROM users WHERE id=?", (uid,)).fetchone()
    if not user: abort(404)
    otp = _clean_yubikey_otp(request.form.get("otp"))
    valid, message, _status = validate_yubikey_otp(otp)
    if not valid:
        flash(message, "error"); return redirect(url_for("admin_users"))
    public_id = _yubikey_public_id(otp)
    existing = db.execute("SELECT user_id FROM yubikey_otp_credentials WHERE public_id=?", (public_id,)).fetchone()
    if existing:
        flash("That YubiKey is already registered to a user.", "error"); return redirect(url_for("admin_users"))
    device_name = (request.form.get("device_name") or "YubiKey").strip()[:100] or "YubiKey"
    db.execute("INSERT INTO yubikey_otp_credentials(user_id,public_id,device_name,created_at) VALUES(?,?,?,?)",
               (uid, public_id, device_name, now_standard()))
    db.commit()
    flash(f"YubiKey OTP registered for {user['username']}.", "success")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:uid>/yubikey/clear")
@admin_required
def admin_user_yubikey_clear(uid):
    db = get_db()
    db.execute("DELETE FROM yubikey_otp_credentials WHERE user_id=?", (uid,)); db.commit()
    flash("Registered YubiKey OTP keys removed.", "success")
    return redirect(url_for("admin_users"))


@app.post("/login/yubikey-otp")
def yubikey_otp_login():
    username = (request.form.get("username") or "").strip()
    otp = _clean_yubikey_otp(request.form.get("otp"))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    public_id = _yubikey_public_id(otp) if len(otp) >= 12 else ""
    key = db.execute("SELECT * FROM yubikey_otp_credentials WHERE user_id=? AND public_id=?",
                     (user["id"], public_id)).fetchone() if user else None
    if not user or not key:
        flash("The username and YubiKey do not match.", "error"); return redirect(url_for("login"))
    valid, message, _status = validate_yubikey_otp(otp)
    if not valid:
        flash(message, "error"); return redirect(url_for("login"))
    db.execute("UPDATE yubikey_otp_credentials SET last_used_at=? WHERE id=?", (now_standard(), key["id"]))
    db.commit()
    requested_section = session.get("requested_section")
    if requested_section not in SECTION_LABELS:
        return redirect(url_for("main_menu"))
    if not user["is_admin"]:
        section_access = db.execute("SELECT allowed FROM section_permissions WHERE user_id=? AND section_key=?",
                                     (user["id"], requested_section)).fetchone()
        if not section_access or not section_access["allowed"]:
            flash(f"Your account does not have access to {SECTION_LABELS[requested_section]}.", "error")
            return redirect(url_for("main_menu"))
    session.clear()
    session["user_id"] = user["id"]; session["username"] = user["username"]
    session["is_admin"] = bool(user["is_admin"])
    session["active_section"] = requested_section
    session["requested_section"] = requested_section
    return redirect(first_allowed_url())


@app.route("/admin/tickets")
@permission_required("manage_tickets")
def admin_tickets():
    db = get_db()
    rows = db.execute("""SELECT t.*, u.username AS technician FROM tickets t
        LEFT JOIN users u ON u.id = t.assigned_to
        ORDER BY t.stock_code, t.id DESC""").fetchall()
    stock_groups = {}
    for r in rows:
        stock_groups.setdefault(r["stock_code"], {"stock_code": r["stock_code"], "tickets": []})["tickets"].append(dict(r))
    return render_template("admin_tickets.html", grouped_tickets=list(stock_groups.values()), total_tickets_count=len(rows))


@app.post("/admin/tickets/add")
@admin_required
def admin_tickets_add():
    stock = (request.form.get("stock_code") or "").strip()
    mrs = (request.form.get("mrs_ticket") or "").strip()
    serial = (request.form.get("serial_number") or "").strip()
    comments = (request.form.get("mrs_comments") or "").strip()
    if not stock or not mrs:
        flash("Stock code and MRS ticket are required.", "error")
    else:
        db = get_db()
        db.execute("INSERT INTO tickets (stock_code, mrs_ticket, serial_number, mrs_comments, created_at) VALUES (?, ?, ?, ?, ?)",
                   (stock, mrs, serial, comments, now_standard()))
        db.commit()
        flash(f"Ticket {mrs} added successfully.", "success")
    return redirect(url_for("admin_tickets"))


@app.post("/admin/tickets/bulk")
@admin_required
def admin_tickets_bulk():
    raw = request.form.get("bulk") or ""; db = get_db(); added = skipped = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        parts = [p.strip() for p in re.split(r"[,\t;|]+", line) if p.strip()]
        if len(parts) < 2: skipped += 1; continue
        sc = parts[0]; mrs = parts[1]
        serial = parts[2] if len(parts) > 2 else ""
        comms = " ".join(parts[3:]) if len(parts) > 3 else ("" if len(parts) > 2 else "")
        if len(parts) == 3 and not parts[2].startswith("SN-") and len(parts[2]) > 15:
            serial = ""; comms = parts[2]
        db.execute("INSERT INTO tickets (stock_code, mrs_ticket, serial_number, mrs_comments, created_at) VALUES (?, ?, ?, ?, ?)",
                   (sc, mrs, serial, comms, now_standard()))
        added += 1
    db.commit()
    flash(f"Bulk import: {added} added, {skipped} skipped.", "success" if added else "error")
    return redirect(url_for("admin_tickets"))


@app.post("/admin/tickets/<int:tid>/delete")
@admin_required
def admin_tickets_delete(tid):
    db = get_db()
    db.execute("DELETE FROM tickets WHERE id=?", (tid,)); db.commit()
    flash("Ticket deleted.", "success")
    return redirect(url_for("admin_tickets"))


@app.route("/admin/database")
@admin_required
def admin_database():
    db = get_db()
    ticket_count = db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    return render_template("admin_database.html", db_path=DB_PATH,
                           ticket_count=ticket_count, user_count=user_count, db_size=db_size)
    
@app.route("/tester-db", methods=["GET", "POST"])
@permission_required("tester_db")
def tester_db():
    db = get_db()
    UPLOAD_DIR = os.path.join(DATA_DIR, "tester_uploads")
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "save":
            tid = request.form.get("id")
            category = (request.form.get("category") or "DIMM").strip()
            brand = (request.form.get("brand") or "").strip()
            memory_type = (request.form.get("memory_type") or "").strip()
            osv_tester = (request.form.get("osv_tester") or "").strip()
            username = (request.form.get("username") or "").strip()
            password = (request.form.get("password") or "").strip()
            mac_address = (request.form.get("mac_address") or "").strip()
            ip_address = (request.form.get("ip_address") or "").strip()
            location = (request.form.get("location") or "").strip()
            remote_access = (request.form.get("remote_access") or "").strip()
            script_version = (request.form.get("script_version") or "").strip()
            all_stockcode = (request.form.get("all_stockcode") or "").strip()
            os_version = (request.form.get("os_version") or "").strip()
            bios = (request.form.get("bios") or "").strip()
            bmc = (request.form.get("bmc") or "").strip()
            work_instruction = (request.form.get("work_instruction") or "").strip()
            last_maintenance_date = (request.form.get("last_maintenance_date") or datetime.date.today().isoformat()).strip()

            if not osv_tester or not brand:
                flash("OSV Tester name and Brand are required.", "error")
            else:
                if tid:
                    db.execute("""
                        UPDATE tester_database SET category=?, brand=?, memory_type=?, osv_tester=?,
                            tester_name=?, username=?, password=?, mac_address=?, ip_address=?, location=?,
                            remote_access=?, script_version=?, all_stockcode=?, os_version=?, bios=?, bmc=?,
                            work_instruction=?, last_maintenance_date=?, updated_at=? WHERE id=?
                    """, (category, brand, memory_type, osv_tester, osv_tester, username, password, mac_address,
                          ip_address, location, remote_access, script_version, all_stockcode,
                          os_version, bios, bmc, work_instruction, last_maintenance_date, now_standard(), tid))
                    flash(f"Tester '{osv_tester}' updated successfully.", "success")
                else:
                    db.execute("""
                        INSERT INTO tester_database (category, brand, memory_type, osv_tester, tester_name,
                            username, password, mac_address, ip_address, location, remote_access, script_version,
                            all_stockcode, os_version, bios, bmc, work_instruction, last_maintenance_date, images, comments, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', ?)
                    """, (category, brand, memory_type, osv_tester, osv_tester, username, password, mac_address,
                          ip_address, location, remote_access, script_version, all_stockcode,
                          os_version, bios, bmc, work_instruction, last_maintenance_date, now_standard()))
                    flash(f"New tester '{osv_tester}' added successfully.", "success")
                db.commit()

        elif action == "delete":
            tid = request.form.get("id")
            if tid:
                db.execute("DELETE FROM tester_database WHERE id=?", (tid,))
                db.commit()
                flash("Tester record deleted.", "success")

        elif action == "comment":
            tid = request.form.get("id")
            comment_text = (request.form.get("comment_text") or "").strip()
            if tid and comment_text:
                row = db.execute("SELECT comments FROM tester_database WHERE id=?", (tid,)).fetchone()
                if row:
                    comments = json.loads(row["comments"] or "[]")
                    comments.append({
                        "user": session.get("username", "Admin"),
                        "time": now_standard(),
                        "text": comment_text
                    })
                    db.execute("UPDATE tester_database SET comments=? WHERE id=?", (json.dumps(comments), tid))
                    db.commit()
                    flash("Comment added.", "success")

        elif action == "upload_image":
            tid = request.form.get("id")
            file = request.files.get("tester_image")
            if tid and file and file.filename:
                filename = f"tester_{tid}_{secrets.token_hex(4)}_{file.filename}"
                file.save(os.path.join(UPLOAD_DIR, filename))
                row = db.execute("SELECT images FROM tester_database WHERE id=?", (tid,)).fetchone()
                if row:
                    images = json.loads(row["images"] or "[]")
                    images.append(filename)
                    db.execute("UPDATE tester_database SET images=? WHERE id=?", (json.dumps(images), tid))
                    db.commit()
                    flash("Image uploaded successfully.", "success")

        return redirect(url_for("tester_db"))

    q = (request.args.get("q") or "").strip()
    sql = "SELECT * FROM tester_database"
    params = []
    if q:
        sql += " WHERE osv_tester LIKE ? OR brand LIKE ? OR all_stockcode LIKE ? OR ip_address LIKE ?"
        params = [f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"]
    sql += " ORDER BY category COLLATE NOCASE, brand COLLATE NOCASE, osv_tester COLLATE NOCASE"
    raw_records = db.execute(sql, params).fetchall()

    today = datetime.date.today()
    processed_records = []
    for r in raw_records:
        item = dict(r)
        item["images_list"] = json.loads(item["images"] or "[]")
        item["comments_list"] = json.loads(item["comments"] or "[]")
        
        last_maint = item["last_maintenance_date"]
        if last_maint:
            try:
                last_dt = datetime.datetime.strptime(last_maint, "%Y-%m-%d").date()
                next_maint = last_dt + datetime.timedelta(days=30)
                days_left = (next_maint - today).days
                item["days_till_maintenance"] = days_left
                item["maintenance_status"] = "overdue" if days_left < 0 else ("warning" if days_left <= 5 else "ok")
            except ValueError:
                item["days_till_maintenance"] = "-"
                item["maintenance_status"] = "ok"
        else:
            item["days_till_maintenance"] = "-"
            item["maintenance_status"] = "ok"
        processed_records.append(item)

    hierarchy = {}
    for rec in processed_records:
        cat = rec["category"] or "DIMM"
        brd = rec["brand"] or "Unbranded"
        mem = rec["memory_type"] or "Standard"
        hierarchy.setdefault(cat, {}).setdefault(brd, {}).setdefault(mem, []).append(rec)

    return render_template("tester_db.html", hierarchy=hierarchy, q=q)


@app.route("/tester-db/export.csv")
@permission_required("tester_db")
def tester_db_export_csv():
    db = get_db()
    rows = db.execute("SELECT * FROM tester_database ORDER BY category, brand, osv_tester").fetchall()
    buf = StringIO()
    w = csv.writer(buf)
    w.writerow([
        "Category", "Brand", "Memory Type", "OSV Tester", "Username", "Password",
        "MAC Address", "IP Address", "Location", "Remote Access", "Script Version",
        "All Stockcode", "OS", "BIOS", "BMC", "Work Instruction", "Last Maintenance Date"
    ])
    for r in rows:
        w.writerow([
            r["category"] or "", r["brand"] or "", r["memory_type"] or "",
            r["osv_tester"] or r["tester_name"] or "", r["username"] or "", r["password"] or "",
            r["mac_address"] or "", r["ip_address"] or "", r["location"] or "",
            r["remote_access"] or "", r["script_version"] or "", r["all_stockcode"] or "",
            r["os_version"] or "", r["bios"] or "", r["bmc"] or "",
            r["work_instruction"] or "", r["last_maintenance_date"] or ""
        ])
    filename = f"tester_database_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.post("/tester-db/import-csv")
@permission_required("tester_db")
def tester_db_import_csv():
    if "csv_file" not in request.files:
        flash("No CSV file selected.", "error")
        return redirect(url_for("tester_db"))
    file = request.files["csv_file"]
    if file.filename == "":
        flash("No selected file.", "error")
        return redirect(url_for("tester_db"))

    db = get_db()
    added = 0
    try:
        stream = io.TextIOWrapper(file.stream, encoding="utf-8-sig")
        reader = csv.DictReader(stream)
        for row in reader:
            category = (row.get("Category") or row.get("category") or "DIMM").strip()
            brand = (row.get("Brand") or row.get("brand") or "Generic").strip()
            memory_type = (row.get("Memory Type") or row.get("memory_type") or "DDR5").strip()
            osv_tester = (row.get("OSV Tester") or row.get("osv_tester") or row.get("Tester Name") or row.get("tester_name") or "").strip()
            if not osv_tester:
                continue

            username = (row.get("Username") or row.get("username") or "").strip()
            password = (row.get("Password") or row.get("password") or "").strip()
            mac_address = (row.get("MAC Address") or row.get("mac_address") or "").strip()
            ip_address = (row.get("IP Address") or row.get("ip_address") or "").strip()
            location = (row.get("Location") or row.get("location") or "").strip()
            remote_access = (row.get("Remote Access") or row.get("remote_access") or "").strip()
            script_version = (row.get("Script Version") or row.get("script_version") or "").strip()
            all_stockcode = (row.get("All Stockcode") or row.get("all_stockcode") or "").strip()
            os_version = (row.get("OS") or row.get("os_version") or "").strip()
            bios = (row.get("BIOS") or row.get("bios") or "").strip()
            bmc = (row.get("BMC") or row.get("bmc") or "").strip()
            work_instruction = (row.get("Work Instruction") or row.get("work_instruction") or "").strip()
            last_maint = (row.get("Last Maintenance Date") or row.get("last_maintenance_date") or datetime.date.today().isoformat()).strip()

            db.execute("""
                INSERT INTO tester_database (category, brand, memory_type, osv_tester, tester_name, username, password,
                    mac_address, ip_address, location, remote_access, script_version, all_stockcode,
                    os_version, bios, bmc, work_instruction, last_maintenance_date, images, comments, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', ?)
            """, (category, brand, memory_type, osv_tester, osv_tester, username, password, mac_address,
                  ip_address, location, remote_access, script_version, all_stockcode, os_version,
                  bios, bmc, work_instruction, last_maint, now_standard()))
            added += 1
        db.commit()
        flash(f"Successfully imported {added} tester records from CSV.", "success")
    except Exception as exc:
        flash(f"Error importing CSV: {exc}", "error")

    return redirect(url_for("tester_db"))

    q = (request.args.get("q") or "").strip()
    sql = "SELECT * FROM tester_database"
    params = []
    if q:
        sql += " WHERE osv_tester LIKE ? OR brand LIKE ? OR all_stockcode LIKE ? OR ip_address LIKE ?"
        params = [f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"]
    sql += " ORDER BY category COLLATE NOCASE, brand COLLATE NOCASE, osv_tester COLLATE NOCASE"
    raw_records = db.execute(sql, params).fetchall()

    today = datetime.date.today()
    processed_records = []
    for r in raw_records:
        item = dict(r)
        item["images_list"] = json.loads(item["images"] or "[]")
        item["comments_list"] = json.loads(item["comments"] or "[]")
        
        # Calculate maintenance timer (30 days cycle)
        last_maint = item["last_maintenance_date"]
        if last_maint:
            try:
                last_dt = datetime.datetime.strptime(last_maint, "%Y-%m-%d").date()
                next_maint = last_dt + datetime.timedelta(days=30)
                days_left = (next_maint - today).days
                item["days_till_maintenance"] = days_left
                item["maintenance_status"] = "overdue" if days_left < 0 else ("warning" if days_left <= 5 else "ok")
            except ValueError:
                item["days_till_maintenance"] = "-"
                item["maintenance_status"] = "ok"
        else:
            item["days_till_maintenance"] = "-"
            item["maintenance_status"] = "ok"
        processed_records.append(item)

    # Build hierarchical tree: Category -> Brand -> MemoryType -> Testers
    hierarchy = {}
    for rec in processed_records:
        cat = rec["category"] or "General"
        brd = rec["brand"] or "Unbranded"
        mem = rec["memory_type"] or "Standard"
        hierarchy.setdefault(cat, {}).setdefault(brd, {}).setdefault(mem, []).append(rec)

    return render_template("tester_db.html", hierarchy=hierarchy, q=q)

@app.route("/tester-db/uploads/<filename>")
@permission_required("tester_db")
def tester_uploaded_file(filename):
    return send_file(os.path.join(DATA_DIR, "tester_uploads", filename))


@app.route("/admin/database/download")
@admin_required
def admin_database_download():
    if not os.path.exists(DB_PATH):
        abort(404)
    return send_file(DB_PATH, as_attachment=True,
                     download_name=f"mrs_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db")


@app.post("/admin/database/import-db")
@admin_required
def admin_database_import_db():
    file = request.files.get("db_file")
    if not file or not file.filename:
        flash("No file uploaded.", "error"); return redirect(url_for("admin_database"))
    fd, tmp_path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    try:
        file.save(tmp_path)
        src = sqlite3.connect(tmp_path); src.row_factory = sqlite3.Row
        tables = {r["name"] for r in src.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "tickets" not in tables:
            flash("Uploaded database has no 'tickets' table.", "error")
            return redirect(url_for("admin_database"))
        src_cols = {r["name"] for r in src.execute("PRAGMA table_info(tickets)").fetchall()}
        db = get_db()
        tgt_cols = {r["name"] for r in db.execute("PRAGMA table_info(tickets)").fetchall()}
        common = sorted(src_cols & tgt_cols)
        if not common:
            flash("No matching columns between uploaded and current schema.", "error")
            return redirect(url_for("admin_database"))
        clear_first = request.form.get("clear_first") == "1"
        if clear_first: db.execute("DELETE FROM tickets")
        col_list = ", ".join(common); placeholders = ", ".join("?" for _ in common)
        sql = f"INSERT INTO tickets ({col_list}) VALUES ({placeholders})"
        src_rows = src.execute(f"SELECT {col_list} FROM tickets").fetchall()
        count = 0
        for row in src_rows:
            try: db.execute(sql, [row[c] for c in common]); count += 1
            except sqlite3.Error: pass
        db.commit(); src.close()
        flash(f"Imported {count} tickets from uploaded database (cleared first: {clear_first}).", "success")
    except Exception as e:
        flash(f"Import failed: {e}", "error")
    finally:
        try: os.unlink(tmp_path)
        except OSError: pass
    return redirect(url_for("admin_database"))


@app.post("/admin/database/import-csv")
@admin_required
def admin_database_import_csv():
    file = request.files.get("csv_file")
    if not file or not file.filename:
        flash("No CSV file uploaded.", "error"); return redirect(url_for("admin_database"))
    try:
        stream = io.TextIOWrapper(file.stream, encoding="utf-8-sig")
        reader = csv.DictReader(stream)
        db = get_db()
        mapping = {
            "stock_code": ["Stock Code","stock_code","StockCode"],
            "mrs_ticket": ["MRS Ticket","mrs_ticket","Title","MRSTicket"],
            "serial_number": ["Serial Number","serial_number","Part SN","SN"],
            "mrs_comments": ["Comments","mrs_comments","Notes"],
            "technician_name": ["Technician","technician_name"],
            "part_type": ["Part Type","part_type"],
            "part_description": ["Part Description","part_description"],
            "wh_location": ["WH Location","wh_location"],
            "test_result": ["Result","test_result"],
            "failure_reason": ["Test Failure","failure_reason"],
            "completed_at": ["Test End Time","completed_at","Return Time"],
            "assigned_at": ["Assigned Time","assigned_at"],
            "test_started_at": ["Test Start Time","test_started_at"],
            "return_time": ["Return Time","return_time"],
            "quality_disposition": ["Quality Disposition","quality_disposition"],
        }
        clear_first = request.form.get("clear_first") == "1"
        if clear_first: db.execute("DELETE FROM tickets")
        count = 0; now = now_standard()
        for row in reader:
            def get(key):
                for candidate in mapping.get(key, []):
                    if candidate in row and row[candidate]: return row[candidate].strip()
                return ""
            stock = get("stock_code") or "STK-UNKNOWN"
            mrs = get("mrs_ticket")
            if not mrs: continue
            db.execute("""INSERT INTO tickets (stock_code, mrs_ticket, serial_number, mrs_comments,
                status, technician_name, test_result, failure_reason, completed_at, assigned_at,
                test_started_at, part_type, part_description, wh_location, return_time,
                quality_disposition, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (stock, mrs, get("serial_number"), get("mrs_comments"),
                 'completed' if get("test_result") else 'available',
                 get("technician_name"), get("test_result"), get("failure_reason"),
                 get("completed_at") or None, get("assigned_at") or None, get("test_started_at") or None,
                 get("part_type"), get("part_description"), get("wh_location"),
                 get("return_time"), get("quality_disposition"), now))
            count += 1
        db.commit()
        flash(f"Imported {count} rows from CSV (cleared first: {clear_first}).", "success")
    except Exception as e:
        flash(f"CSV import failed: {e}", "error")
    return redirect(url_for("admin_database"))


def register_feature_modules():
    import pkgutil, importlib
    package_name = (__package__ + ".features") if __package__ else "features"
    try:
        package = importlib.import_module(package_name)
        for info in pkgutil.iter_modules(package.__path__):
            if info.name.startswith("_"): continue
            module = importlib.import_module(package_name + "." + info.name)
            register = getattr(module, "register", None)
            if callable(register): register(app)
    except ImportError:
        pass


register_feature_modules()


def ensure_certificate():
    cert_path = os.path.join(CERT_DIR, "cert.pem"); key_path = os.path.join(CERT_DIR, "key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    try:
        import ipaddress
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        lan_ip = get_lan_ip()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MRS Dashboard")])
        alt = [x509.DNSName("localhost"), x509.DNSName(socket.gethostname()),
               x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
        try: alt.append(x509.IPAddress(ipaddress.IPv4Address(lan_ip)))
        except Exception: pass
        san = x509.SubjectAlternativeName(alt)
        now = datetime.datetime.utcnow()
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(san, critical=False).sign(key, hashes.SHA256()))
        with open(key_path, "wb") as fh:
            fh.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption()))
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        try: os.chmod(key_path, 0o600)
        except OSError: pass
        return cert_path, key_path
    except ImportError:
        pass
    import shutil, subprocess as sp
    if shutil.which("openssl"):
        lan_ip = get_lan_ip()
        sp.check_call(["openssl","req","-x509","-newkey","rsa:2048","-nodes",
                       "-keyout",key_path,"-out",cert_path,"-days","3650",
                       "-subj","/CN=localhost","-addext",
                       f"subjectAltName=DNS:localhost,IP:127.0.0.1,IP:{lan_ip}"],
                      stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        return cert_path, key_path
    raise RuntimeError("Cannot generate a TLS certificate.")


class ServerThread(threading.Thread):
    def __init__(self, mode):
        super().__init__(daemon=True)
        self.mode = mode
        if mode == "https":
            cert, key = ensure_certificate()
            self.port = HTTPS_PORT
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert, keyfile=key)
            ssl_context = ctx
        else:
            self.port = HTTP_PORT; ssl_context = None
        init_db()
        try:
            from .sharepoint_sync import start_sharepoint_sync
        except ImportError:
            from sharepoint_sync import start_sharepoint_sync
        self.sharepoint_worker = start_sharepoint_sync(DB_PATH, BASE_DIR)
        self.httpd = make_server(BIND_HOST, self.port, app, threaded=True, ssl_context=ssl_context)
    def run(self): self.httpd.serve_forever()
    def stop(self):
        worker = getattr(self, "sharepoint_worker", None)
        if worker is not None:
            worker.stop()
        try: self.httpd.shutdown()
        except Exception: pass


BG = "#0f172a"; CARD = "#16213e"; CARD_HOVER = "#1c2b4d"
LINE = "#243456"; TEXT = "#e6ecf7"; MUTED = "#93a3c0"; ACCENT = "#4f8cff"; OK = "#22c55e"


if HAS_TK:
    class Launcher(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("MRS Ticket Dashboard - Host Launcher")
            self.geometry("600x600"); self.minsize(600, 600)
            self.configure(bg=BG)
            self.server = None; self.local_url = None; self.net_url = None
            self._build()
        def _build(self):
            header = tk.Frame(self, bg=BG); header.pack(fill="x", pady=(20, 2))
            tk.Label(header, text="MRS Ticket Dashboard", bg=BG, fg=TEXT,
                     font=("Segoe UI", 18, "bold")).pack()
            tk.Label(header, text="Pick how to publish the app, then share the Network URL.",
                     bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(pady=(4, 0))
            body = tk.Frame(self, bg=BG); body.pack(fill="x", padx=24, pady=14)
            self._mode_button(body, "HTTP   -   port 8080",
                              "Plain HTTP. Browsers on other machines will show a Not secure warning.",
                              lambda: self.start("http")).pack(fill="x", pady=5)
            self._mode_button(body, "HTTPS   -   port 443",
                              "Encrypted with a self-signed certificate.\nNeeds administrator / root.",
                              lambda: self.start("https")).pack(fill="x", pady=5)
            url_box = tk.Frame(self, bg=BG); url_box.pack(fill="x", padx=24, pady=(6, 0))
            self.status = tk.Label(url_box, text="Server stopped.", bg=BG, fg=MUTED,
                                   font=("Segoe UI", 10), justify="left", anchor="w", wraplength=550)
            self.status.pack(fill="x")
            tk.Label(url_box, text="Local (this machine)", bg=BG, fg=MUTED,
                     font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x", pady=(10, 0))
            row_local = tk.Frame(url_box, bg=BG); row_local.pack(fill="x")
            self.local_label = tk.Label(row_local, text="-", bg=BG, fg=ACCENT,
                                        font=("Consolas", 11, "underline"), cursor="hand2", anchor="w")
            self.local_label.pack(side="left", fill="x", expand=True)
            self.local_label.bind("<Button-1>", lambda _e: self._open(self.local_url))
            tk.Button(row_local, text="Open", command=lambda: self._open(self.local_url),
                      bg=CARD, fg=TEXT, relief="flat", padx=10, pady=2,
                      font=("Segoe UI", 9), cursor="hand2").pack(side="right")
            tk.Label(url_box, text="Network (other computers)", bg=BG, fg=MUTED,
                     font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x", pady=(10, 0))
            row_net = tk.Frame(url_box, bg=BG); row_net.pack(fill="x")
            self.net_label = tk.Label(row_net, text="-", bg=BG, fg=OK,
                                      font=("Consolas", 12, "bold"), cursor="hand2", anchor="w")
            self.net_label.pack(side="left", fill="x", expand=True)
            self.net_label.bind("<Button-1>", lambda _e: self._copy_net())
            tk.Button(row_net, text="Copy", command=self._copy_net, bg=CARD, fg=TEXT,
                      relief="flat", padx=10, pady=2, font=("Segoe UI", 9), cursor="hand2").pack(side="right")
            fw = tk.Frame(self, bg=BG); fw.pack(fill="x", padx=24, pady=(12, 0))
            self.fw_btn = tk.Button(fw, text="Open firewall port (needs admin)",
                                    command=self._open_firewall, bg=CARD, fg=TEXT,
                                    activebackground=CARD_HOVER, activeforeground=TEXT,
                                    relief="flat", font=("Segoe UI", 9), padx=12, pady=5,
                                    cursor="hand2", state="disabled")
            self.fw_btn.pack(side="left")
            tk.Label(fw, text="Run this once so other computers can connect.",
                     bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=10)
            self.stop_btn = tk.Button(self, text="Stop server", command=self.stop,
                                      bg="#1e293b", fg=TEXT, activebackground="#334155",
                                      activeforeground="#ffffff", relief="flat",
                                      font=("Segoe UI", 10), padx=14, pady=7,
                                      state="disabled", cursor="hand2")
            self.stop_btn.pack(pady=14)
            tk.Label(self, text="First sign-in:   admin / admin123   - change it immediately.",
                     bg=BG, fg="#64748b", font=("Segoe UI", 9)).pack(side="bottom", pady=10)
        def _mode_button(self, parent, title, subtitle, command):
            frame = tk.Frame(parent, bg=CARD, highlightbackground=LINE,
                             highlightthickness=1, cursor="hand2")
            lbl1 = tk.Label(frame, text=title, bg=CARD, fg=TEXT,
                            font=("Segoe UI", 13, "bold"), anchor="w")
            lbl1.pack(fill="x", padx=16, pady=(11, 0))
            lbl2 = tk.Label(frame, text=subtitle, bg=CARD, fg=MUTED,
                            font=("Segoe UI", 9), anchor="w", justify="left")
            lbl2.pack(fill="x", padx=16, pady=(3, 11))
            def hover(on):
                bg = CARD_HOVER if on else CARD
                border = ACCENT if on else LINE
                frame.configure(bg=bg, highlightbackground=border)
                lbl1.configure(bg=bg); lbl2.configure(bg=bg)
            for w in (frame, lbl1, lbl2):
                w.bind("<Button-1>", lambda _e, c=command: c())
                w.bind("<Enter>", lambda _e: hover(True))
                w.bind("<Leave>", lambda _e: hover(False))
            return frame
        def _open(self, url):
            if url: webbrowser.open(url)
        def _copy_net(self):
            if not self.net_url: return
            self.clipboard_clear(); self.clipboard_append(self.net_url)
            self.status.configure(text=f"Copied to clipboard: {self.net_url}")
        def _open_firewall(self):
            port = self.server.port if self.server else HTTP_PORT
            ok, msg = open_firewall_rule(port)
            if ok:
                messagebox.showinfo("Firewall", f"Rule added for TCP {port}.")
            else:
                messagebox.showerror("Firewall", msg)
        def start(self, mode):
            if self.server is not None:
                messagebox.showinfo("Already running", "Stop the current server first."); return
            try:
                server = ServerThread(mode)
            except PermissionError:
                messagebox.showerror("Permission denied",
                                     f"Port {HTTPS_PORT if mode=='https' else HTTP_PORT} requires elevated privileges.")
                return
            except OSError as exc:
                messagebox.showerror("Cannot bind port", str(exc)); return
            except Exception as exc:
                messagebox.showerror("Startup failed", str(exc)); return
            self.server = server; server.start()
            scheme = "https" if mode == "https" else "http"
            lan_ip = get_lan_ip()
            self.local_url = f"{scheme}://localhost:{server.port}"
            self.net_url = f"{scheme}://{lan_ip}:{server.port}"
            self.status.configure(text=f"Running ({mode.upper()}) on port {server.port}.")
            self.local_label.configure(text=self.local_url)
            self.net_label.configure(text=self.net_url)
            self.stop_btn.configure(state="normal"); self.fw_btn.configure(state="normal")
        def stop(self):
            if self.server is not None:
                self.server.stop(); self.server = None
            self.local_url = None; self.net_url = None
            self.status.configure(text="Server stopped.")
            self.local_label.configure(text="-"); self.net_label.configure(text="-")
            self.stop_btn.configure(state="disabled"); self.fw_btn.configure(state="disabled")
        def on_close(self):
            self.stop(); self.destroy()


def console_launcher():
    print("MRS Ticket Dashboard - console launcher")
    print("  1) HTTP  on port 8080"); print("  2) HTTPS on port 443")
    mode = "https" if input("Select [1/2]: ").strip() == "2" else "http"
    try:
        server = ServerThread(mode)
    except PermissionError:
        print("Port needs elevated privileges."); return
    except Exception as exc:
        print(f"Startup failed: {exc}"); return
    server.start()
    scheme = "https" if mode == "https" else "http"
    print(f"\nLocal:    {scheme}://localhost:{server.port}")
    print(f"Network:  {scheme}://{get_lan_ip()}:{server.port}")
    print("\nPress Ctrl+C to stop.\n")
    try:
        while True:
            server.join(1)
            if not server.is_alive(): break
    except KeyboardInterrupt:
        print("\nShutting down..."); server.stop()


def main():
    if HAS_TK:
        l = Launcher(); l.protocol("WM_DELETE_WINDOW", l.on_close); l.mainloop()
    else:
        console_launcher()


if __name__ == "__main__":
    main()






