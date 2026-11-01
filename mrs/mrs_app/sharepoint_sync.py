"""Reliable, non-blocking SharePoint ticket synchronization via Microsoft Graph.

The web request commits to SQLite first. SQLite triggers then place the ticket in a
transactional outbox. A background worker upserts the latest ticket snapshot to a
SharePoint list. SharePoint outages therefore never block technicians.
"""
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

WORKER = None


def _load_config(base_dir):
    path = Path(os.environ.get("MRS_SHAREPOINT_CONFIG", Path(base_dir) / "data" / "sharepoint_config.json"))
    if not path.is_file():
        return None, path
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    required = ("tenant_id", "client_id", "client_secret", "site_id", "list_id")
    missing = [name for name in required if not str(data.get(name, "")).strip()]
    if missing:
        raise RuntimeError("SharePoint config is missing: " + ", ".join(missing))
    data.setdefault("enabled", True)
    data.setdefault("poll_seconds", 3)
    data.setdefault("max_attempts", 12)
    return data, path


def install_outbox(db_path):
    db = sqlite3.connect(db_path, timeout=30)
    try:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS sharepoint_sync_outbox (
            ticket_id INTEGER PRIMARY KEY,
            operation TEXT NOT NULL DEFAULT 'upsert',
            queued_at TEXT NOT NULL DEFAULT (datetime('now')),
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT,
            last_error TEXT,
            synced_at TEXT
        );
        CREATE TABLE IF NOT EXISTS sharepoint_sync_state (
            ticket_id INTEGER PRIMARY KEY,
            sharepoint_item_id TEXT,
            last_synced_at TEXT,
            last_error TEXT
        );
        CREATE TRIGGER IF NOT EXISTS trg_sp_ticket_insert
        AFTER INSERT ON tickets BEGIN
            INSERT INTO sharepoint_sync_outbox(ticket_id, operation, queued_at, attempts, next_attempt_at, last_error, synced_at)
            VALUES (NEW.id, 'upsert', datetime('now'), 0, NULL, NULL, NULL)
            ON CONFLICT(ticket_id) DO UPDATE SET operation='upsert', queued_at=datetime('now'),
                attempts=0, next_attempt_at=NULL, last_error=NULL, synced_at=NULL;
        END;
        CREATE TRIGGER IF NOT EXISTS trg_sp_ticket_update
        AFTER UPDATE ON tickets BEGIN
            INSERT INTO sharepoint_sync_outbox(ticket_id, operation, queued_at, attempts, next_attempt_at, last_error, synced_at)
            VALUES (NEW.id, 'upsert', datetime('now'), 0, NULL, NULL, NULL)
            ON CONFLICT(ticket_id) DO UPDATE SET operation='upsert', queued_at=datetime('now'),
                attempts=0, next_attempt_at=NULL, last_error=NULL, synced_at=NULL;
        END;
        CREATE TRIGGER IF NOT EXISTS trg_sp_ticket_delete
        AFTER DELETE ON tickets BEGIN
            INSERT INTO sharepoint_sync_outbox(ticket_id, operation, queued_at, attempts, next_attempt_at, last_error, synced_at)
            VALUES (OLD.id, 'delete', datetime('now'), 0, NULL, NULL, NULL)
            ON CONFLICT(ticket_id) DO UPDATE SET operation='delete', queued_at=datetime('now'),
                attempts=0, next_attempt_at=NULL, last_error=NULL, synced_at=NULL;
        END;
        """)
        db.commit()
    finally:
        db.close()


class GraphClient:
    def __init__(self, config):
        self.config = config
        self.token = None
        self.token_expires = 0

    def _request(self, method, url, body=None, auth=True):
        headers = {"Accept": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + self.get_token()
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Graph HTTP {exc.code}: {detail[:1000]}") from exc

    def get_token(self):
        if self.token and time.time() < self.token_expires - 120:
            return self.token
        tenant = urllib.parse.quote(self.config["tenant_id"])
        url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        form = urllib.parse.urlencode({
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }).encode("ascii")
        request = urllib.request.Request(url, data=form, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Token HTTP {exc.code}: {detail[:1000]}") from exc
        self.token = payload["access_token"]
        self.token_expires = time.time() + int(payload.get("expires_in", 3600))
        return self.token

    @property
    def list_base(self):
        site = urllib.parse.quote(self.config["site_id"], safe=",")
        list_id = urllib.parse.quote(self.config["list_id"])
        return f"https://graph.microsoft.com/v1.0/sites/{site}/lists/{list_id}"

    def find_item(self, ticket_id):
        value = urllib.parse.quote(str(ticket_id), safe="")
        params = urllib.parse.urlencode({"$filter": f"fields/LocalTicketId eq '{value}'", "$select": "id"})
        payload = self._request("GET", f"{self.list_base}/items?expand=fields&{params}")
        items = payload.get("value", [])
        return str(items[0]["id"]) if items else None

    def upsert(self, ticket, existing_item_id=None):
        fields = ticket_to_fields(ticket)
        item_id = existing_item_id or self.find_item(ticket["id"])
        if item_id:
            self._request("PATCH", f"{self.list_base}/items/{item_id}/fields", fields)
            return item_id
        result = self._request("POST", f"{self.list_base}/items", {"fields": fields})
        return str(result["id"])

    def delete(self, item_id):
        if item_id:
            self._request("DELETE", f"{self.list_base}/items/{item_id}")


def _text(value):
    return "" if value is None else str(value)


def ticket_to_fields(ticket):
    fields = {
        "Title": _text(ticket["mrs_ticket"] or ticket["stock_code"] or ticket["id"]),
        "LocalTicketId": _text(ticket["id"]),
        "StockCode": _text(ticket["stock_code"]),
        "MRSTicket": _text(ticket["mrs_ticket"]),
        "SerialNumber": _text(ticket["serial_number"]),
        "Status": _text(ticket["status"]),
        "AssignedToUserId": _text(ticket["assigned_to"]),
        "AssignedAt": _text(ticket["assigned_at"]),
        "TechnicianName": _text(ticket["technician_name"]),
        "TestStartedAt": _text(ticket["test_started_at"]),
        "TestResult": _text(ticket["test_result"]),
        "FailureReason": _text(ticket["failure_reason"]),
        "MRSComments": _text(ticket["mrs_comments"]),
        "CompletedAt": _text(ticket["completed_at"]),
        "CreatedAt": _text(ticket["created_at"]),
        "WHLocation": _text(ticket["wh_location"]),
        "PartType": _text(ticket["part_type"]),
        "PartDescription": _text(ticket["part_description"]),
        "ReturnTime": _text(ticket["return_time"]),
        "QualityDisposition": _text(ticket["quality_disposition"]),
        "LogsUploaded": _text(ticket["logs_uploaded"]),
        "LogPath": _text(ticket["log_path"]),
        "TransferCount": int(ticket["transfer_count"] or 0),
        "LastSyncedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return {key: value for key, value in fields.items() if value != "" or key in {"Title", "LocalTicketId"}}


class SharePointSyncWorker(threading.Thread):
    def __init__(self, db_path, config):
        super().__init__(daemon=True, name="SharePointSyncWorker")
        self.db_path = db_path
        self.config = config
        self.graph = GraphClient(config)
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        while not self.stop_event.wait(float(self.config.get("poll_seconds", 3))):
            try:
                self.process_batch()
            except Exception as exc:
                print("SharePoint sync worker error:", exc)

    def process_batch(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            rows = db.execute("""
                SELECT * FROM sharepoint_sync_outbox
                WHERE synced_at IS NULL AND (next_attempt_at IS NULL OR next_attempt_at <= datetime('now'))
                ORDER BY queued_at LIMIT 25
            """).fetchall()
            for job in rows:
                self.process_job(db, job)
        finally:
            db.close()

    def process_job(self, db, job):
        ticket_id = int(job["ticket_id"])
        state = db.execute("SELECT * FROM sharepoint_sync_state WHERE ticket_id=?", (ticket_id,)).fetchone()
        try:
            if job["operation"] == "delete":
                self.graph.delete(state["sharepoint_item_id"] if state else None)
                db.execute("DELETE FROM sharepoint_sync_state WHERE ticket_id=?", (ticket_id,))
            else:
                ticket = db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
                if ticket is None:
                    self.graph.delete(state["sharepoint_item_id"] if state else None)
                    db.execute("DELETE FROM sharepoint_sync_state WHERE ticket_id=?", (ticket_id,))
                else:
                    item_id = self.graph.upsert(ticket, state["sharepoint_item_id"] if state else None)
                    db.execute("""INSERT INTO sharepoint_sync_state(ticket_id,sharepoint_item_id,last_synced_at,last_error)
                                  VALUES(?,?,datetime('now'),NULL)
                                  ON CONFLICT(ticket_id) DO UPDATE SET sharepoint_item_id=excluded.sharepoint_item_id,
                                  last_synced_at=datetime('now'),last_error=NULL""", (ticket_id, item_id))
            db.execute("UPDATE sharepoint_sync_outbox SET synced_at=datetime('now'),last_error=NULL WHERE ticket_id=?", (ticket_id,))
            db.commit()
        except Exception as exc:
            attempts = int(job["attempts"] or 0) + 1
            delay = min(3600, 15 * (2 ** min(attempts - 1, 8)))
            db.execute("""UPDATE sharepoint_sync_outbox SET attempts=?, last_error=?,
                          next_attempt_at=datetime('now', ?) WHERE ticket_id=?""",
                       (attempts, str(exc)[:2000], f"+{delay} seconds", ticket_id))
            db.execute("""INSERT INTO sharepoint_sync_state(ticket_id,last_error) VALUES(?,?)
                          ON CONFLICT(ticket_id) DO UPDATE SET last_error=excluded.last_error""",
                       (ticket_id, str(exc)[:2000]))
            db.commit()


def start_sharepoint_sync(db_path, base_dir):
    global WORKER
    install_outbox(db_path)
    config, path = _load_config(base_dir)
    if not config or not config.get("enabled", True):
        print(f"SharePoint sync disabled. Config path: {path}")
        return None
    if WORKER and WORKER.is_alive():
        return WORKER
    WORKER = SharePointSyncWorker(db_path, config)
    WORKER.start()
    print(f"SharePoint sync enabled for site {config['site_id']} list {config['list_id']}")
    return WORKER
