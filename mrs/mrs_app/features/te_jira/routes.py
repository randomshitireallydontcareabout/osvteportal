"""Search the QFT JIRA Azure SQL view by exact IssueId."""
import os
import struct
import threading
import time
from contextlib import closing

from flask import Blueprint, render_template, request

bp = Blueprint("te_jira", __name__, template_folder="templates")

DEFAULT_SERVER = "zwhirlpoolr.9d0348b8c92d.database.windows.net,1433"
DEFAULT_DATABASE = "JIRA"
DEFAULT_VIEW = "[dbo].[vw_QFT_JiraIssues]"
SQL_COPT_SS_ACCESS_TOKEN = 1256
SQL_TOKEN_SCOPE = "https://database.windows.net/.default"
TOKEN_REFRESH_MARGIN_SECONDS = 300

# Keep one credential and one token cache for the lifetime of the portal process.
# The lock prevents two Flask request threads from starting overlapping browser
# authentication flows, which can cause an OAuth state mismatch.
_credential = None
_credential_lock = threading.Lock()
_token_lock = threading.Lock()
_cached_access_token = None
_cached_access_token_expires_on = 0


def _setting(name, default):
    return (os.environ.get(name) or default).strip()


def _get_credential():
    """Create InteractiveBrowserCredential once and reuse it."""
    global _credential

    if _credential is not None:
        return _credential

    with _credential_lock:
        if _credential is None:
            try:
                from azure.identity import InteractiveBrowserCredential
            except ImportError as exc:
                raise RuntimeError(
                    "JIRA search requires azure-identity. Install it in the same "
                    "Python environment used to run the portal."
                ) from exc

            options = {
                "timeout": int(_setting("TE_JIRA_AUTH_TIMEOUT", "300")),
            }
            tenant_id = _setting("TE_JIRA_TENANT_ID", "")
            client_id = _setting("TE_JIRA_CLIENT_ID", "")
            login_hint = _setting("TE_JIRA_LOGIN_HINT", "")
            redirect_uri = _setting("TE_JIRA_REDIRECT_URI", "")

            if tenant_id:
                options["tenant_id"] = tenant_id
            if client_id:
                options["client_id"] = client_id
            if login_hint:
                options["login_hint"] = login_hint
            if redirect_uri:
                options["redirect_uri"] = redirect_uri

            _credential = InteractiveBrowserCredential(**options)

    return _credential


def _get_sql_access_token():
    """Return a cached SQL token and serialize any required browser login."""
    global _cached_access_token, _cached_access_token_expires_on

    now = int(time.time())
    if (
        _cached_access_token
        and _cached_access_token_expires_on > now + TOKEN_REFRESH_MARGIN_SECONDS
    ):
        return _cached_access_token

    with _token_lock:
        # Check again after waiting because another request may have refreshed it.
        now = int(time.time())
        if (
            _cached_access_token
            and _cached_access_token_expires_on > now + TOKEN_REFRESH_MARGIN_SECONDS
        ):
            return _cached_access_token

        access_token = _get_credential().get_token(SQL_TOKEN_SCOPE)
        _cached_access_token = access_token.token
        _cached_access_token_expires_on = int(access_token.expires_on)
        return _cached_access_token


def _connect():
    """Open Azure SQL using the authenticated and cached Entra access token."""
    try:
        import pyodbc
    except ImportError as exc:
        raise RuntimeError(
            "JIRA search requires pyodbc. Install it in the same Python "
            "environment used to run the portal."
        ) from exc

    server = _setting("TE_JIRA_SQL_SERVER", DEFAULT_SERVER)
    database = _setting("TE_JIRA_SQL_DATABASE", DEFAULT_DATABASE)
    driver = _setting("TE_JIRA_ODBC_DRIVER", "ODBC Driver 18 for SQL Server")

    token = _get_sql_access_token()
    token_bytes = token.encode("utf-16-le")
    token_struct = struct.pack("=i", len(token_bytes)) + token_bytes

    connection_string = (
        f"Driver={{{driver}}};"
        f"Server={server};"
        f"Database={database};"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
        "Connection Timeout=20;"
    )
    return pyodbc.connect(
        connection_string,
        attrs_before={SQL_COPT_SS_ACCESS_TOKEN: token_struct},
        timeout=20,
    )


def _find_issue(issue_id):
    """Return one JIRA row as ordered field/value pairs."""
    view_name = _setting("TE_JIRA_SQL_VIEW", DEFAULT_VIEW)
    if not (view_name.startswith("[") and "].[" in view_name and view_name.endswith("]")):
        raise RuntimeError("TE_JIRA_SQL_VIEW must look like [schema].[view_name].")

    query = f"SELECT TOP (1) * FROM {view_name} WHERE IssueId = ?;"
    with closing(_connect()) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute(query, int(issue_id))
            row = cursor.fetchone()
            if row is None:
                return None
            columns = [item[0] for item in cursor.description]
            return list(zip(columns, row))


def _get_current_week_open_tickets():
    """Return tickets created Monday through Sunday whose IssueStatus is not Closed."""
    view_name = _setting("TE_JIRA_SQL_VIEW", DEFAULT_VIEW)
    if not (view_name.startswith("[") and "].[" in view_name and view_name.endswith("]")):
        raise RuntimeError("TE_JIRA_SQL_VIEW must look like [schema].[view_name].")

    query = f"""
        SET DATEFIRST 1;
        DECLARE @WeekStart date = DATEADD(day, 1 - DATEPART(weekday, GETDATE()), CAST(GETDATE() AS date));
        DECLARE @WeekEnd date = DATEADD(day, 7, @WeekStart);

        SELECT
            IssueId,
            IssueKey,
            IssueSummary,
            IssueStatus,
            Assignee,
            Originator,
            [Responsible Team] AS ResponsibleTeam,
            Vendor,
            [FA Level] AS FALevel,
            IssueCreatedDateTime,
            IssueUpdatedDate,
            IssueDueDate
        FROM {view_name}
        WHERE IssueCreatedDateTime >= @WeekStart
          AND IssueCreatedDateTime < @WeekEnd
          AND LOWER(LTRIM(RTRIM(COALESCE(IssueStatus, '')))) <> 'closed'
        ORDER BY
            CASE WHEN IssueDueDate IS NULL THEN 1 ELSE 0 END,
            IssueDueDate ASC,
            IssueCreatedDateTime DESC;
    """

    with closing(_connect()) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute(query)
            columns = [item[0] for item in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]

    status_counts = {}
    assignees = set()
    for row in rows:
        status = str(row.get("IssueStatus") or "Unspecified").strip() or "Unspecified"
        status_counts[status] = status_counts.get(status, 0) + 1
        assignee = str(row.get("Assignee") or "").strip()
        if assignee:
            assignees.add(assignee)

    return rows, status_counts, len(assignees)


def register(app):
    if bp.name in app.blueprints:
        return

    core = __import__(
        app.import_name,
        fromlist=["section_required", "te_permission_required"],
    )

    @bp.route("/te/jira", methods=["GET", "POST"])
    @core.section_required("te")
    @core.te_permission_required("te_jira")
    def index():
        issue_id = (request.values.get("issue_id") or "").strip()
        ticket = None
        searched = False
        error = None
        weekly_tickets = []
        weekly_status_counts = {}
        weekly_assignee_count = 0
        weekly_error = None

        try:
            weekly_tickets, weekly_status_counts, weekly_assignee_count = _get_current_week_open_tickets()
        except Exception as exc:
            weekly_error = str(exc)

        if issue_id:
            searched = True
            if not issue_id.isdigit():
                error = "IssueId must contain numbers only."
            else:
                try:
                    ticket = _find_issue(issue_id)
                except Exception as exc:
                    error = str(exc)

        return render_template(
            "te_jira/index.html",
            issue_id=issue_id,
            ticket=ticket,
            searched=searched,
            error=error,
            weekly_tickets=weekly_tickets,
            weekly_status_counts=weekly_status_counts,
            weekly_assignee_count=weekly_assignee_count,
            weekly_error=weekly_error,
        )

    app.register_blueprint(bp)
