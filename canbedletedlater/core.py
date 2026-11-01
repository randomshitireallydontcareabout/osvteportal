#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MRS Ticket Dashboard - single-file app.
"""

import os, subprocess, sys, time, importlib

BOOTSTRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_PACKAGE_PREFIX = ".mrs_packages_py{}{}".format(sys.version_info.major, sys.version_info.minor)
REQUIRED_PIP_PACKAGES = ("flask","werkzeug","markupsafe","jinja2","cryptography","fpdf2")
REQUIRED_IMPORTS = ("flask","werkzeug","markupsafe","jinja2","cryptography","fpdf")


def _validate_package_dir(package_dir):
    if not os.path.isdir(package_dir):
        return False
    check_code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                  "import flask, werkzeug, markupsafe, jinja2, cryptography, fpdf; print('ok')")
    try:
        result = subprocess.run([sys.executable,"-c",check_code,package_dir],
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                                timeout=60,check=False)
        return result.returncode == 0 and "ok" in result.stdout
    except (OSError, subprocess.SubprocessError):
        return False


def _find_valid_local_packages():
    try:
        names = sorted(os.listdir(BOOTSTRAP_DIR), reverse=True)
    except OSError:
        return None
    for name in names:
        if name.startswith(LOCAL_PACKAGE_PREFIX):
            candidate = os.path.join(BOOTSTRAP_DIR, name)
            if _validate_package_dir(candidate):
                return candidate
    return None


def ensure_packages():
    package_dir = _find_valid_local_packages()
    if package_dir is None:
        unique_name = "{}_{}_{}".format(LOCAL_PACKAGE_PREFIX, int(time.time()), os.getpid())
        package_dir = os.path.join(BOOTSTRAP_DIR, unique_name)
        os.makedirs(package_dir, exist_ok=False)
        print("Preparing project-local packages...")
        command = [sys.executable,"-m","pip","install","--disable-pip-version-check",
                   "--no-warn-script-location","--no-input","--target",package_dir,*REQUIRED_PIP_PACKAGES]
        try:
            subprocess.check_call(command)
        except (subprocess.CalledProcessError, PermissionError, OSError) as exc:
            print("Could not install packages:", exc); sys.exit(1)
        if not _validate_package_dir(package_dir):
            print("Local package verification failed."); sys.exit(1)
    if package_dir in sys.path:
        sys.path.remove(package_dir)
    sys.path.insert(0, package_dir)
    importlib.invalidate_caches()


ensure_packages()

import os, re, csv, ssl, math, socket, sqlite3, secrets, datetime, base64, json
import urllib.parse, urllib.request, urllib.error, hmac, hashlib, threading, webbrowser, io
import tempfile
from io import StringIO, BytesIO
from functools import wraps
from flask import (Flask, g, render_template, request, redirect, url_for, session,
                   flash, abort, Response, jsonify, send_file)
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
    db.executescript(SCHEMA)
    cols = {r["name"] for r in db.execute("PRAGMA table_info(tickets)")}
    for col, ctype in [
        ("technician_name","TEXT"),("test_started_at","TEXT"),("test_result","TEXT"),
        ("failure_reason","TEXT"),("mrs_comments","TEXT"),("serial_number","TEXT"),
        ("wh_location","TEXT"),("part_type","TEXT"),("part_description","TEXT"),
        ("return_time","TEXT"),("quality_disposition","TEXT"),("logs_uploaded","TEXT"),
        ("log_path","TEXT"),("stock_cd","TEXT"),("bb_flag","INTEGER"),
        ("sxm1_flag","INTEGER"),("sxm2_flag","INTEGER"),("sxm3_flag","INTEGER"),
        ("sxm4_flag","INTEGER"),("sxm5_flag","INTEGER"),("sxm6_flag","INTEGER"),
        ("sxm7_flag","INTEGER"),("sxm8_flag","INTEGER"),("csv_id","INTEGER"),
        ("csv_index","TEXT"),("modified","TEXT"),("transfer_count","INTEGER NOT NULL DEFAULT 0")
    ]:
        if col not in cols:
            db.execute(f"ALTER TABLE tickets ADD COLUMN {col} {ctype}")

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
                   f'<span style="flex:1;color:#c6d2e6">{label}</span>'
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
                   f'<span style="flex:1;color:#c6d2e6">{label}</span>'
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
    "te_alerts":"Alerts","te_kpi":"KPI","te_tools":"Tools",
}
TE_ADMIN_TABS = {"te_manage_users":"Manage Users"}
TE_ENDPOINTS = {
    "te_pie_tickets":"te_pie_tickets.index","te_history":"te_history.index",
    "te_dashboard":"te_dashboard.index","te_alerts":"te_alerts.index","te_kpi":"te_kpi.index",
    "te_tools":"tools_portal.index",
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
            return redirect(url_for("overview"))
        flash("User not found.", "error")
    return render_template("login.html", selected_section="osv", selected_section_label="OSV")


@app.route("/logout")
def logout():
    session.clear(); flash("Signed out.", "success"); return redirect(url_for("main_menu"))


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

    if session.get("is_admin"):
        total_unclaimed = db.execute("SELECT COUNT(*) FROM tickets WHERE status='available'").fetchone()[0]
        total_assigned = db.execute("SELECT COUNT(*) FROM tickets WHERE status='assigned'").fetchone()[0]
        today_chart = Markup(pie_chart([("Available (Unclaimed)", total_unclaimed, "#4f8cff"),
                                         ("Assigned (In Progress)", total_assigned, "#f59e0b")],
                                        title="Unclaimed Stock vs Assigned Work", size=150))
    else:
        today_chart = Markup(pie_chart([("Available", available_today, "#4f8cff"),
                                         ("In progress", assigned_today, "#f59e0b"),
                                         ("Completed", completed_today, "#22c55e")],
                                        title=f"Status on {day_str_fmt}", size=150))
    today_std = datetime.date.today().strftime("%Y/%m/%d")
    ctx = {"day": day_str_fmt, "raw_date_val": raw_date_val, "today": today_std,
           "prev_day": (day - datetime.timedelta(days=1)).strftime("%Y/%m/%d"),
           "next_day": (day + datetime.timedelta(days=1)).strftime("%Y/%m/%d"),
           "is_today": (day == datetime.date.today()),
           "received": len(todays), "available_today": available_today,
           "assigned_today": assigned_today, "completed_today": completed_today,
           "completed_on_day": completed_on_day, "today_chart": today_chart,
           "grouped_tickets": grouped_tickets, "total_available_count": len(raw_available),
           "q": q, "tech_minis": [], "my_chart": None}

    if session.get("is_admin"):
        day_passed = db.execute("SELECT COUNT(*) FROM tickets WHERE test_result='passed' AND completed_at LIKE ?", (day_prefix,)).fetchone()[0]
        day_failed = db.execute("SELECT COUNT(*) FROM tickets WHERE test_result='failed' AND completed_at LIKE ?", (day_prefix,)).fetchone()[0]
        day_not_tested = db.execute("SELECT COUNT(*) FROM tickets WHERE test_result='not_tested' AND completed_at LIKE ?", (day_prefix,)).fetchone()[0]
        day_not_run = db.execute("SELECT COUNT(*) FROM tickets WHERE (status='available' OR (status='assigned' AND test_result IS NULL)) AND (created_at LIKE ? OR assigned_at LIKE ?)", (day_prefix, day_prefix)).fetchone()[0]
        ctx["admin_results_chart"] = Markup(pie_chart([
            ("Passed", day_passed, "#22c55e"),
            ("Failed", day_failed, "#ef4444"),
            ("Not Tested", day_not_tested, "#f59e0b"),
            ("Not Tested / Avail", day_not_run, "#4f8cff")
        ], title=f"Stock Code Results on {day_str_fmt}", size=150))
        day_avail_count = db.execute("SELECT COUNT(*) FROM tickets WHERE status='available' AND created_at LIKE ?", (day_prefix,)).fetchone()[0]
        day_prog_count = db.execute("SELECT COUNT(*) FROM tickets WHERE status='assigned' AND assigned_at LIKE ?", (day_prefix,)).fetchone()[0]
        day_comp_count = completed_on_day
        ctx["admin_status_chart"] = Markup(pie_chart([
            ("Available", day_avail_count, "#4f8cff"),
            ("In Progress", day_prog_count, "#f59e0b"),
            ("Completed", day_comp_count, "#22c55e")
        ], title=f"Ticket Status Breakdown ({day_str_fmt})", size=150))
        tech_breakdown_rows = db.execute("""
            SELECT u.username,
                SUM(CASE WHEN (t.assigned_at LIKE ? OR t.completed_at LIKE ?) THEN 1 ELSE 0 END) AS assigned_day,
                SUM(CASE WHEN t.status='completed' AND t.completed_at LIKE ? THEN 1 ELSE 0 END) AS completed_day,
                SUM(CASE WHEN t.status='assigned' AND t.assigned_at LIKE ? THEN 1 ELSE 0 END) AS wip_day
            FROM users u JOIN tickets t ON t.assigned_to = u.id
            GROUP BY u.id, u.username
            HAVING assigned_day > 0 OR completed_day > 0 OR wip_day > 0
            ORDER BY u.username COLLATE NOCASE
        """, (day_prefix, day_prefix, day_prefix, day_prefix)).fetchall()
        ctx["tech_breakdown_charts"] = [{"username": r["username"], "assigned": r["assigned_day"] or 0,
                                          "completed": r["completed_day"] or 0, "wip": r["wip_day"] or 0,
                                          "chart": Markup(pie_chart([("Completed", r["completed_day"] or 0, "#22c55e"),
                                                                     ("Incomplete (WIP)", r["wip_day"] or 0, "#f59e0b")], size=130))}
                                         for r in tech_breakdown_rows]
    else:
        me = db.execute("""SELECT COUNT(t.id) AS total,
            SUM(CASE WHEN t.status='completed' THEN 1 ELSE 0 END) AS completed,
            SUM(CASE WHEN t.status='assigned' THEN 1 ELSE 0 END) AS in_progress
            FROM tickets t WHERE t.assigned_to = ? AND (t.assigned_at LIKE ? OR t.completed_at LIKE ?)""",
            (session["user_id"], day_prefix, day_prefix)).fetchone()
        if me and me["total"]:
            ctx["my_chart"] = Markup(pie_chart([("Completed", me["completed"] or 0, "#22c55e"),
                                                 ("In progress", me["in_progress"] or 0, "#f59e0b")],
                                                title=f"Your progress on {day_str_fmt}", size=150))
    return render_template("overview.html", **ctx)


@app.route("/my-tickets")
@permission_required("my_tickets")
def my_tickets():
    db = get_db()
    rows = db.execute("SELECT * FROM tickets WHERE assigned_to=? AND status='assigned' ORDER BY stock_code, id",
                      (session["user_id"],)).fetchall()
    users = db.execute("SELECT id, username FROM users ORDER BY username COLLATE NOCASE").fetchall()
    stock_groups = {}
    for r in rows:
        stock_groups.setdefault(r["stock_code"], {"stock_code": r["stock_code"], "tickets": []})["tickets"].append(dict(r))
    return render_template("my_tickets.html", grouped_tickets=list(stock_groups.values()),
                           users=users, in_progress_count=len(rows), total_count=len(rows))


@app.route("/my-completed")
@permission_required("my_completed")
def my_completed():
    db = get_db()
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
# ==== END DEV ONLY ====


from fpdf import FPDF
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


class KPIPresentationPDF(FPDF):
    def __init__(self, dept_name="OSV", admin_name="Administrator"):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.dept_name = dept_name; self.admin_name = admin_name
    def header(self):
        self.set_fill_color(15, 23, 42); self.rect(0, 0, 210, 28, "F")
        self.set_xy(12, 6); self.set_font("helvetica", "B", 15)
        self.set_text_color(255, 255, 255)
        self.cell(0, 7, f"DEPARTMENT KPI REPORT - {self.dept_name}", 0, 1, "L")
        self.set_xy(12, 14); self.set_font("helvetica", "", 9)
        self.set_text_color(147, 197, 253)
        self.cell(0, 5, f"On-Site Verification (OSV) | Management Sign-Off: {self.admin_name}", 0, 1, "L")
        self.ln(12)
    def footer(self):
        self.set_y(-15); self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()} | Generated on {now_standard()} | Managed by {self.admin_name} ({self.dept_name})", 0, 0, "C")


def create_chart_image(data_dict, title, chart_type='pie'):
    """Render a chart as a PNG buffer for embedding in PDF."""
    is_pie_like = chart_type in ('pie', 'donut')
    figsize = (3.2, 3.2) if is_pie_like else (4.4, 2.8)
    fig, ax = plt.subplots(
        figsize=figsize,
        subplot_kw=dict(aspect="equal") if is_pie_like else None,
    )
    fig.patch.set_facecolor('#f8fafc')
    ax.set_facecolor('#f8fafc')

    labels = list(data_dict.keys())
    sizes = list(data_dict.values())
    color_map = {
        'Completed Work': '#22c55e', 'In-Progress (WIP)': '#f59e0b',
        'NTF': '#22c55e', 'Failed': '#ef4444', 'CUSTOMER INDUCED DAMAGE (CID)': '#a855f7',
        'Not Tested': '#f59e0b', 'Pending / WIP': '#4f8cff',
        'Passed': '#22c55e', 'Available': '#4f8cff',
        'In Progress': '#f59e0b', 'Completed': '#22c55e',
    }
    default_colors = ['#22c55e', '#ef4444', '#3b82f6', '#f59e0b', '#a855f7', '#64748b', '#06b6d4', '#ec4899']
    colors = [color_map.get(l, default_colors[i % len(default_colors)]) for i, l in enumerate(labels)]

    if sum(sizes) == 0:
        labels = ['No Data']; sizes = [1]; colors = ['#cbd5e1']

    if chart_type in ('pie', 'donut', 'treemap', 'radial', 'stat'):
        wedgeprops = dict(width=0.55) if chart_type == 'donut' else None
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels if chart_type != 'donut' else None,
            autopct='%1.0f%%' if sum(sizes) > 0 else None,
            startangle=90, colors=colors,
            textprops=dict(color="#1e293b", fontsize=8),
            wedgeprops=wedgeprops,
        )
        if sum(sizes) > 0:
            plt.setp(autotexts, size=8, weight="bold", color="white")
        if chart_type == 'donut':
            ax.legend(labels, loc='center left', bbox_to_anchor=(1.05, 0.5),
                      fontsize=8, frameon=False)
    elif chart_type == 'hbar':
        y_pos = list(range(len(labels)))
        bars = ax.barh(y_pos, sizes, color=colors)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=9, color='#1e293b')
        ax.invert_yaxis()
        total = sum(sizes) or 1
        for bar, v in zip(bars, sizes):
            ax.text(bar.get_width() + max(sizes) * 0.02,
                    bar.get_y() + bar.get_height() / 2,
                    f'{v} ({v / total * 100:.0f}%)',
                    va='center', fontsize=8, color='#475569')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.tick_params(axis='x', labelsize=8, colors='#64748b')
    elif chart_type == 'vbar':
        x_pos = list(range(len(labels)))
        bars = ax.bar(x_pos, sizes, color=colors)
        ax.set_xticks(x_pos)
        ax.set_xticklabels([l if len(l) <= 10 else l[:9] + '…' for l in labels],
                           fontsize=8, color='#1e293b')
        for bar, v in zip(bars, sizes):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + max(sizes) * 0.02,
                    f'{v}', ha='center', fontsize=8, color='#475569', fontweight='bold')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.tick_params(axis='y', labelsize=8, colors='#64748b')
    else:
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels,
            autopct='%1.0f%%' if sum(sizes) > 0 else None,
            startangle=90, colors=colors,
            textprops=dict(color="#1e293b", fontsize=8),
        )
        if sum(sizes) > 0:
            plt.setp(autotexts, size=8, weight="bold", color="white")

    ax.set_title(title, fontsize=10, fontweight='bold', color='#0f172a', pad=6)
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=150,
                facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close(fig)
    buf.seek(0)
    return buf


@app.route("/admin/kpi/pdf")
@permission_required("kpi")
def admin_kpi_pdf():
    db = get_db()
    admin_name = session.get("username", "Admin")
    dept_name = "OSV"
    chart_type = normalize_chart_type(request.args.get("chart"))
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

    def name_tokens(v):
        t = "".join(ch if ch.isalnum() else " " for ch in (v or "").casefold())
        return tuple(sorted(p for p in t.split() if p))

    def names_match(a, b):
        if not a or not b:
            return False
        return name_key(a) == name_key(b) or name_tokens(a) == name_tokens(b)

    date_from = parse_filter_date(request.args.get("from"), current_week_start)
    date_to = parse_filter_date(request.args.get("to"), current_week_end)
    if date_from > date_to:
        date_from, date_to = date_to, date_from
    tech_id = (request.args.get("tech") or "").strip()

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

    # ------------------------------------------------------------------
    # Build the PDF
    # ------------------------------------------------------------------
    pdf = KPIPresentationPDF(dept_name=dept_name, admin_name=admin_name)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Filter summary bar
    pdf.set_fill_color(240, 244, 248)
    pdf.rect(10, 31, 190, 24, "F")
    pdf.set_xy(12, 33)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(15, 23, 42)
    filter_desc = f"Date Range: {date_from.strftime('%m/%d/%Y')} to {date_to.strftime('%m/%d/%Y')}"
    if tech_id and tech_id != "All Technicians":
        filter_desc += f"  |  Technician: {selected_tech_name or tech_id}"
    else:
        filter_desc += "  |  Technician: All Technicians"
    filter_desc += f"  |  Chart: {chart_type.title()}"
    pdf.cell(0, 5, f"OSV Executive Summary  |  {filter_desc}", 0, 1, "L")

    pdf.set_xy(12, 40)
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(30, 41, 59)
    summary_line = (f"Total Tickets: {total_work}   |   Completed: {completed_count}"
                    f"   |   WIP: {wip_count}   |   Active Techs: {len(active_techs)}")
    pdf.cell(0, 5, summary_line, 0, 1, "L")

    pdf_chart_type = chart_type
    if pdf_chart_type in ("stat", "treemap", "radial"):
        pdf_chart_type = "pie"  # PDF fallback

    work_breakdown_data = {'Completed Work': completed_count, 'In-Progress (WIP)': wip_count}
    chart1_buf = create_chart_image(work_breakdown_data, 'Work State Ratio', pdf_chart_type)
    chart2_buf = create_chart_image(
        result_counts if result_counts else {'No Data': 1},
        'Overall Test Results', pdf_chart_type
    )
    pdf.image(chart1_buf, x=15, y=58, w=85)
    pdf.image(chart2_buf, x=110, y=58, w=85)

    # Technician performance table
    pdf.set_y(138)
    pdf.set_font("helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "Technician Test Result Performance", 0, 1, "L")

    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("helvetica", "B", 9)
    pdf.cell(55, 7, "Technician Name", 1, 0, "L", fill=True)
    pdf.cell(27, 7, "Total", 1, 0, "C", fill=True)
    pdf.cell(36, 7, "NTF / Passed", 1, 0, "C", fill=True)
    pdf.cell(36, 7, "Failed", 1, 0, "C", fill=True)
    pdf.cell(36, 7, "Other / WIP", 1, 1, "C", fill=True)

    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(30, 41, 59)
    if tech_map:
        fill = False
        for tech, counts in sorted(tech_map.items(), key=lambda x: x[0].casefold()):
            tot = sum(counts.values())
            ntf_pass = (counts.get("NTF", 0) + counts.get("passed", 0) + counts.get("Passed", 0))
            failed = counts.get("Failed", 0) + counts.get("failed", 0)
            other = tot - (ntf_pass + failed)
            pdf.set_fill_color(248, 250, 252) if fill else pdf.set_fill_color(255, 255, 255)
            pdf.cell(55, 6, str(tech), 1, 0, "L", fill=fill)
            pdf.cell(27, 6, str(tot), 1, 0, "C", fill=fill)
            pdf.cell(36, 6, str(ntf_pass), 1, 0, "C", fill=fill)
            pdf.cell(36, 6, str(failed), 1, 0, "C", fill=fill)
            pdf.cell(36, 6, str(other), 1, 1, "C", fill=fill)
            fill = not fill
    else:
        pdf.cell(190, 6, "No technician records found in range.", 1, 1, "C")

    # Sign-off block
    pdf.ln(8)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "Department Management Authorization", 0, 1, "L")
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 5, f"Verified & Approved by: {admin_name} (Authenticated via YubiKey Security)", 0, 1, "L")
    pdf.cell(0, 5, f"Department: OSV (On-Site Verification)  |  Timestamp: {now_standard()}", 0, 1, "L")

    pdf_buf = io.BytesIO()
    pdf_buf.write(pdf.output())
    pdf_buf.seek(0)
    filename = (f"OSV_KPI_Report_{admin_name}_"
                f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    return send_file(pdf_buf, mimetype="application/pdf",
                     as_attachment=True, download_name=filename)


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
        if not durations: return "—"
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
                             "serial_number": r["serial_number"] or "—",
                             "mrs_comments": r["mrs_comments"] or "No notes provided.",
                             "part_description": r["part_description"] or r["part_type"] or "—",
                             "wh_location": r["wh_location"] or "—"}
                            for r in active_testing_rows]
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
        current_year=current_year,
        chart_type=chart_type)


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
                                    size=160, title=f"Work State Ratio ({display_from} to {display_to})",
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
                                     "chart": Markup(render_chart(chart_data, size=130, chart_type=chart_type))})
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

    def format_duration(seconds):
        if seconds is None: return "—"
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
        "average": format_duration(sum(response_seconds) / len(response_seconds)) if response_seconds else "—",
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

    return render_template(
        "admin_kpi.html",
        users=users, kpi_technicians=kpi_technicians, tech_id=tech_id,
        date_from=date_from_str, date_to=date_to_str,
        total_work=total_work, completed_work=completed_count, wip_work=wip_count,
        active_techs_count=len(active_techs),
        selected_tech_name=selected_tech_name,
        work_pie_chart=work_pie, overall_results_chart=overall_results_pie,
        tech_results_charts=tech_results_charts,
        ticket_rows=rows, kpi_stock_groups=kpi_stock_groups,
        kpi_ticket_details=kpi_ticket_details,
        response_stats=response_stats, response_buckets=response_buckets,
        chart_type=chart_type)


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
                pdf.cell(45, 5, str(t["serial_number"] or "—"), 1, 0, "L")
                pdf.cell(25, 5, str(t["status"]), 1, 0, "C")
                pdf.cell(25, 5, str(t["test_result"] or "pending"), 1, 0, "C")
                pdf.cell(60, 5, str(t["technician"] or "Unassigned"), 1, 1, "L")
            pdf.ln(5)
    pdf_output = BytesIO(); pdf_output.write(pdf.output()); pdf_output.seek(0)
    filename = f"mrs_volume_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(pdf_output, mimetype="application/pdf", as_attachment=True, download_name=filename)


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
    if not ts_str: return "—"
    try:
        for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %H:%M:%S","%Y-%m-%d %H:%M:%S","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M"):
            try:
                dt = datetime.datetime.strptime(ts_str.strip(), fmt)
                return dt.strftime("%Y/%m/%d %I:%M:%S %p")
            except ValueError: continue
        return ts_str
    except Exception: return ts_str


def _turnaround(assigned_at, test_started, completed):
    if not assigned_at or not completed: return "—"
    try:
        start_time_str = test_started if test_started else assigned_at
        for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %H:%M:%S","%Y-%m-%d %H:%M:%S","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M"):
            try: a = datetime.datetime.strptime(start_time_str.strip(), fmt); break
            except ValueError: continue
        else: return "—"
        for fmt in ("%Y/%m/%d %I:%M:%S %p","%Y/%m/%d %H:%M:%S","%Y-%m-%d %H:%M:%S","%m/%d/%Y %I:%M %p","%m/%d/%Y %H:%M"):
            try: b = datetime.datetime.strptime(completed.strip(), fmt); break
            except ValueError: continue
        else: return "—"
        secs = int((b - a).total_seconds())
        if secs < 0: return "—"
        if secs < 60: return f"{secs}s"
        if secs < 3600: return f"{secs // 60}m {secs % 60}s"
        if secs < 86400: return f"{secs // 3600}h {(secs % 3600) // 60}m"
        return f"{secs // 86400}d {(secs % 86400) // 3600}h"
    except Exception: return "—"


@app.route("/history")
@permission_required("history")
def history():
    db = get_db(); f = _history_filter(db); rows = f["rows"]
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
    db = get_db(); f = _history_filter(db); buf = StringIO(); w = csv.writer(buf)
    w.writerow(["Stock Code","Title","Part SN","WH Location","Technician","Part Type","Part Description",
                "Assigned Time","Test Start Time","Test End Time","Return Time","Result","Test Failure",
                "Quality Disposition","Logs Uploaded","Log Path","Comments","Turnaround","Ticket ID"])
    for r in f["rows"]:
        w.writerow([r["stock_code"], r["mrs_ticket"], r["serial_number"] or "", r["wh_location"] or "",
                    r["technician"] or "", r["part_type"] or "", r["part_description"] or "",
                    _format_standard_time(r["assigned_at"]), _format_standard_time(r["test_started_at"]),
                    _format_standard_time(r["completed_at"]), _format_standard_time(r["return_time"]),
                    r["test_result"] or "", r["failure_reason"] or "", r["quality_disposition"] or "",
                    r["logs_uploaded"] or "", r["log_path"] or "", r["mrs_comments"] or "",
                    _turnaround(r["assigned_at"], r["test_started_at"], r["completed_at"]), r["id"]])
    filename = f"mrs_history_{f['date_from'].replace('/', '-')}_to_{f['date_to'].replace('/', '-')}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


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
    if t["assigned_to"] != session["user_id"]:
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
    if t["assigned_to"] != session["user_id"]:
        return jsonify({"success": False, "message": "Not your ticket."}), 403
    if t["status"] != "assigned":
        return jsonify({"success": False, "message": "Ticket not in assigned status."}), 400
    db.execute("UPDATE tickets SET status='completed', completed_at=?, test_result='passed', "
               "failure_reason=NULL, technician_name=? WHERE id=?",
               (now_standard(), session["username"], tid))
    db.commit()
    return jsonify({"success": True})


@app.post("/ticket/<int:tid>/complete-fail-ajax")
@login_required
def complete_fail_ajax(tid):
    db = get_db(); t = _ticket_or_404(db, tid)
    reason = (request.form.get("failure_reason") or "").strip()
    if t["assigned_to"] != session["user_id"]:
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
    if t["assigned_to"] != session["user_id"]:
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
            self.local_label = tk.Label(row_local, text="—", bg=BG, fg=ACCENT,
                                        font=("Consolas", 11, "underline"), cursor="hand2", anchor="w")
            self.local_label.pack(side="left", fill="x", expand=True)
            self.local_label.bind("<Button-1>", lambda _e: self._open(self.local_url))
            tk.Button(row_local, text="Open", command=lambda: self._open(self.local_url),
                      bg=CARD, fg=TEXT, relief="flat", padx=10, pady=2,
                      font=("Segoe UI", 9), cursor="hand2").pack(side="right")
            tk.Label(url_box, text="Network (other computers)", bg=BG, fg=MUTED,
                     font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x", pady=(10, 0))
            row_net = tk.Frame(url_box, bg=BG); row_net.pack(fill="x")
            self.net_label = tk.Label(row_net, text="—", bg=BG, fg=OK,
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
            self.local_label.configure(text="—"); self.net_label.configure(text="—")
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
