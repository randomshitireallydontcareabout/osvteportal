"""Shared TE ticket popup, comments, work sections, and priority controls."""
import importlib
from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request, session

bp = Blueprint("ticket_collaboration", __name__, static_folder="static", static_url_path="/te-ticket-collaboration-static")
VALID_SOURCES = {"jira", "pie"}
VALID_STATUSES = {"Planned", "In Progress", "Blocked", "Completed"}

def _now(): return datetime.now().astimezone().isoformat(timespec="seconds")
def _identity():
    """Use the YubiKey holder name recorded when OTP authentication succeeds."""
    uid = session.get("user_id")
    # audit_yubikey_holder is populated by the portal's YubiKey session logger.
    # Do not use the portal account username unless an older session lacks it.
    name = str(session.get("audit_yubikey_holder") or "").strip()
    if not uid or not name:
        raise PermissionError(
            "A YubiKey holder name is required. Sign out and sign in again with the registered YubiKey."
        )
    return int(uid), name

def _parse_date(value):
    if not value: return None
    text = str(value).strip().replace("Z", "+00:00")
    for parser in (
        lambda: datetime.fromisoformat(text),
        lambda: datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S"),
        lambda: datetime.strptime(text[:10], "%Y-%m-%d"),
    ):
        try:
            dt = parser()
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None

def _automatic_priority(fields):
    """High priority only when open over 14 days or status/priority is Critical."""
    values = {str(x.get("name") or "").strip().lower(): x.get("value") for x in fields}
    status = str(values.get("issuestatus") or values.get("status") or "").strip()
    source_priority = str(values.get("priority") or "").strip()
    created_raw = values.get("issuecreateddatetime") or values.get("created")
    created = _parse_date(created_raw)
    age_days = None
    if created:
        now = datetime.now(timezone.utc)
        if created.tzinfo is None: created = created.replace(tzinfo=timezone.utc)
        age_days = max(0, (now - created.astimezone(timezone.utc)).days)
    is_closed = status.casefold() in {"closed", "resolved", "done", "cancelled", "canceled"}
    critical = status.casefold() == "critical" or source_priority.casefold() == "critical"
    older_than_two_weeks = age_days is not None and age_days > 14 and not is_closed
    high = critical or older_than_two_weeks
    reasons = []
    if critical: reasons.append("Critical status or priority")
    if older_than_two_weeks: reasons.append(f"Open for {age_days} days")
    return {"is_high_priority": high, "reasons": reasons, "age_days": age_days,
            "status": status, "source_priority": source_priority}
def _ticket(source,key):
    source=str(source).lower().strip(); key=str(key).strip()
    if source not in VALID_SOURCES or not key or len(key)>100: raise ValueError("Invalid ticket identifier.")
    return source,key
def _value(v):
    if v is None:return None
    if hasattr(v,"isoformat"):
        try:return v.isoformat(sep=" ",timespec="seconds")
        except TypeError:return v.isoformat()
    return v.hex() if isinstance(v,(bytes,bytearray)) else str(v)
def _external(app,source,key):
    root=app.import_name.rsplit(".",1)[0]
    mod=importlib.import_module(root+(".features.te_jira.routes" if source=="jira" else ".features.te_pie_tickets.routes"))
    fields=mod._find_issue(key) if source=="jira" else mod._find_ticket(key)
    return [] if fields is None else [{"name":str(n),"value":_value(v)} for n,v in fields]

def register(app):
    if bp.name in app.blueprints:return
    core=__import__(app.import_name,fromlist=["get_db","login_required"])
    with app.app_context():
        db=core.get_db(); db.executescript("""
        CREATE TABLE IF NOT EXISTS te_ticket_work_sections(id INTEGER PRIMARY KEY AUTOINCREMENT,source TEXT NOT NULL,ticket_key TEXT NOT NULL,title TEXT NOT NULL,details TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'Planned',author_user_id INTEGER NOT NULL,author_name TEXT NOT NULL,created_at TEXT NOT NULL,updated_by_user_id INTEGER NOT NULL,updated_by_name TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS te_ticket_comments(id INTEGER PRIMARY KEY AUTOINCREMENT,source TEXT NOT NULL,ticket_key TEXT NOT NULL,section_id INTEGER,comment_text TEXT NOT NULL,author_user_id INTEGER NOT NULL,author_name TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS te_ticket_priorities(source TEXT NOT NULL,ticket_key TEXT NOT NULL,is_high_priority INTEGER NOT NULL DEFAULT 0,updated_by_user_id INTEGER NOT NULL,updated_by_name TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(source,ticket_key));
        """);db.commit()
    @bp.get("/te/ticket-collaboration/<source>/<path:key>")
    @core.login_required
    def activity(source,key):
        try: source,key=_ticket(source,key);_identity()
        except Exception as e:return jsonify(ok=False,error=str(e)),400
        db=core.get_db(); sections=[]
        for r in db.execute("SELECT * FROM te_ticket_work_sections WHERE source=? AND ticket_key=? ORDER BY id DESC",(source,key)).fetchall():
            d=dict(r);d["comments"]=[dict(x) for x in db.execute("SELECT * FROM te_ticket_comments WHERE section_id=? ORDER BY id",(r["id"],)).fetchall()];sections.append(d)
        comments=[dict(x) for x in db.execute("SELECT * FROM te_ticket_comments WHERE source=? AND ticket_key=? AND section_id IS NULL ORDER BY id DESC",(source,key)).fetchall()]
        try:
            fields=_external(app,source,key);error=None
            priority=_automatic_priority(fields)
        except Exception as e:
            fields=[];error=str(e);priority={"is_high_priority":False,"reasons":[],"age_days":None}
        return jsonify(ok=True,ticket_fields=fields,ticket_error=error,sections=sections,comments=comments,priority=priority)
    @bp.post("/te/ticket-collaboration/<source>/<path:key>/sections")
    @core.login_required
    def section(source,key):
        try:
            source,key=_ticket(source,key);uid,name=_identity();d=request.get_json(silent=True) or {};title=str(d.get("title") or "").strip();details=str(d.get("details") or "").strip();status=str(d.get("status") or "Planned")
            if not title or status not in VALID_STATUSES:raise ValueError("A title and valid status are required.")
        except Exception as e:return jsonify(ok=False,error=str(e)),400
        now=_now();db=core.get_db();db.execute("INSERT INTO te_ticket_work_sections(source,ticket_key,title,details,status,author_user_id,author_name,created_at,updated_by_user_id,updated_by_name,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(source,key,title,details,status,uid,name,now,uid,name,now));db.commit();return jsonify(ok=True),201
    @bp.patch("/te/ticket-collaboration/sections/<int:sid>")
    @core.login_required
    def status(sid):
        try:uid,name=_identity();value=str((request.get_json(silent=True) or {}).get("status") or "");assert value in VALID_STATUSES
        except Exception:return jsonify(ok=False,error="Invalid status."),400
        db=core.get_db();db.execute("UPDATE te_ticket_work_sections SET status=?,updated_by_user_id=?,updated_by_name=?,updated_at=? WHERE id=?",(value,uid,name,_now(),sid));db.commit();return jsonify(ok=True)
    @bp.post("/te/ticket-collaboration/<source>/<path:key>/comments")
    @core.login_required
    def comment(source,key):
        try:
            source,key=_ticket(source,key);uid,name=_identity();d=request.get_json(silent=True) or {};text=str(d.get("comment") or "").strip();sid=d.get("section_id");sid=int(sid) if sid not in (None,"") else None
            if not text:raise ValueError("Comment is required.")
        except Exception as e:return jsonify(ok=False,error=str(e)),400
        db=core.get_db();db.execute("INSERT INTO te_ticket_comments(source,ticket_key,section_id,comment_text,author_user_id,author_name,created_at) VALUES(?,?,?,?,?,?,?)",(source,key,sid,text,uid,name,_now()));db.commit();return jsonify(ok=True),201
    app.register_blueprint(bp)
