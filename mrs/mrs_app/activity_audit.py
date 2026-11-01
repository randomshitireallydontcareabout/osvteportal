from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from datetime import datetime
from pathlib import Path

_LOG_LOCK = threading.RLock()
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_SENSITIVE_KEYS = {
    "password", "password1", "password2", "current_password", "new_password",
    "otp", "yubikey_otp", "secret", "token", "csrf_token", "client_secret",
    "authorization", "cookie", "session",
}


def _now_local():
    return datetime.now().astimezone()


def _safe_filename(value: str) -> str:
    value = _SAFE_NAME.sub("_", (value or "user").strip()).strip("._")
    return (value or "user")[:80]


def _display(value, fallback="Not recorded"):
    text = str(value or "").strip()
    return text if text else fallback


def mask_yubikey(public_id: str | None) -> str:
    value = (public_id or "").strip()
    if not value:
        return "Not recorded"
    if len(value) <= 10:
        return value[:3] + "..." + value[-2:]
    return value[:6] + "..." + value[-4:]


def sanitize_details(details):
    if details is None:
        return {}
    if not isinstance(details, dict):
        return {"Value": str(details)[:1000]}
    clean = {}
    for key, value in details.items():
        label = str(key).replace("_", " ").strip().title()
        if str(key).lower() in _SENSITIVE_KEYS:
            clean[label] = "[REDACTED]"
        elif isinstance(value, dict):
            clean[label] = sanitize_details(value)
        elif isinstance(value, (list, tuple, set)):
            clean[label] = [str(item)[:500] for item in value][:100]
        else:
            clean[label] = str(value)[:2000]
    return clean


def _write_rule(handle, character="-", width=78):
    handle.write(character * width + "\n")


def create_session_log(data_dir, session_obj, *, user_id, username, is_admin,
                       yubikey_public_id=None, yubikey_name=None,
                       yubikey_holder_name=None, ip_address="", user_agent=""):
    now = _now_local()
    session_id = secrets.token_hex(8)
    holder_name = _display(yubikey_holder_name or username)
    key_name = _display(yubikey_name, "Registered YubiKey")
    masked_id = mask_yubikey(yubikey_public_id)
    day_dir = Path(data_dir) / "user_activity_logs" / now.strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    filename = (
        f"{_safe_filename(holder_name)}_"
        f"{_safe_filename(username)}_"
        f"{now.strftime('%Y-%m-%d_%H-%M-%S')}_{session_id}.txt"
    )
    path = day_dir / filename
    session_obj["audit_session_id"] = session_id
    session_obj["audit_log_path"] = str(path)
    session_obj["audit_login_time"] = now.isoformat(timespec="seconds")
    session_obj["audit_yubikey_holder"] = holder_name
    session_obj["audit_yubikey_name"] = key_name
    session_obj["audit_yubikey_masked"] = masked_id

    with _LOG_LOCK, path.open("w", encoding="utf-8", newline="\n") as handle:
        _write_rule(handle, "=")
        handle.write("                        OSV PORTAL USER ACTIVITY LOG\n")
        _write_rule(handle, "=")
        handle.write("\nUSER AND YUBIKEY IDENTITY\n")
        _write_rule(handle)
        handle.write(f"  YubiKey Holder Name : {holder_name}\n")
        handle.write(f"  Portal Username     : {_display(username)}\n")
        handle.write(f"  User ID             : {user_id}\n")
        handle.write(f"  Account Type        : {'Administrator' if is_admin else 'Technician / User'}\n")
        handle.write(f"  YubiKey Name        : {key_name}\n")
        handle.write(f"  YubiKey Public ID   : {masked_id}\n")
        handle.write("\nSESSION INFORMATION\n")
        _write_rule(handle)
        handle.write(f"  Login Date          : {now.strftime('%A, %B %d, %Y')}\n")
        handle.write(f"  Login Time          : {now.strftime('%I:%M:%S %p %Z')}\n")
        handle.write(f"  Audit Session ID    : {session_id}\n")
        handle.write(f"  IP Address          : {_display(ip_address, 'Unknown')}\n")
        handle.write(f"  Browser / Device    : {_display((user_agent or '')[:500], 'Unknown')}\n")
        handle.write("\nACTIVITY TIMELINE\n")
        _write_rule(handle, "=")
        handle.write("Events are listed in the order they occurred.\n\n")
    return path


def audit_event(session_obj, event_type, *, result="SUCCESS", details=None,
                method="", path="", endpoint="", ip_address=""):
    log_path = session_obj.get("audit_log_path")
    if not log_path:
        return False
    now = _now_local()
    payload = sanitize_details(details)
    title = str(event_type or "ACTIVITY").replace("_", " ").strip().title()
    status = str(result or "SUCCESS").upper()
    try:
        with _LOG_LOCK, open(log_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"[{now.strftime('%I:%M:%S.%f')[:-3]} {now.strftime('%p')}]  {title}\n")
            handle.write(f"  Status              : {status}\n")
            if endpoint:
                handle.write(f"  Area / Action       : {endpoint}\n")
            if method or path:
                handle.write(f"  Request             : {(method or 'ACTION').upper()} {_display(path, '/')}\n")
            if ip_address:
                handle.write(f"  Source IP           : {ip_address}\n")
            if payload:
                handle.write("  Details:\n")
                for key, value in payload.items():
                    if isinstance(value, dict):
                        handle.write(f"    - {key}:\n")
                        for nested_key, nested_value in value.items():
                            handle.write(f"        {nested_key}: {nested_value}\n")
                    elif isinstance(value, list):
                        handle.write(f"    - {key}:\n")
                        for item in value:
                            handle.write(f"        * {item}\n")
                    else:
                        handle.write(f"    - {key}: {value}\n")
            handle.write("\n")
            handle.flush()
        return True
    except OSError:
        return False


def close_session_log(session_obj, *, reason="LOGOUT"):
    path_text = session_obj.get("audit_log_path")
    if not path_text:
        return
    now = _now_local()
    login_text = session_obj.get("audit_login_time")
    duration = "Unknown"
    try:
        started = datetime.fromisoformat(login_text)
        seconds = max(0, int((now - started).total_seconds()))
        duration = f"{seconds // 3600:02d}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"
    except Exception:
        pass
    audit_event(session_obj, reason, details={"Session duration": duration})
    path = Path(path_text)
    try:
        with _LOG_LOCK:
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                _write_rule(handle, "=")
                handle.write("SESSION SUMMARY\n")
                _write_rule(handle)
                handle.write(f"  YubiKey Holder Name : {_display(session_obj.get('audit_yubikey_holder'))}\n")
                handle.write(f"  Session Duration    : {duration}\n")
                handle.write(f"  Log Closed          : {now.strftime('%A, %B %d, %Y at %I:%M:%S %p %Z')}\n")
                handle.write(f"  Integrity SHA256    : {digest}\n")
                _write_rule(handle, "=")
    except OSError:
        pass
