"""TE PIE ticket search backed by SBIDev.dbo.tbl_API_Jira_PIE."""
import os
import re
from contextlib import closing

from flask import Blueprint, render_template, request

bp = Blueprint("te_pie_tickets", __name__, template_folder="templates")

DEFAULT_SERVER = "WQMSDEV01"
DEFAULT_DATABASE = "SBIDev"
DEFAULT_TABLE = "[dbo].[tbl_API_Jira_PIE]"
PROJECT_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,50}$")


def _setting(name, default):
    return (os.environ.get(name) or default).strip()


def _table_name():
    table_name = _setting("TE_PIE_SQL_TABLE", DEFAULT_TABLE)
    if not (table_name.startswith("[") and "].[" in table_name and table_name.endswith("]")):
        raise RuntimeError("TE_PIE_SQL_TABLE must look like [schema].[table_name].")
    return table_name


def _connect():
    """Open SQL Server using the Windows account running the TE Portal."""
    try:
        import pyodbc
    except ImportError as exc:
        raise RuntimeError(
            "PIE search requires pyodbc. Install it in the same Python environment "
            "used to run the portal."
        ) from exc

    server = _setting("TE_PIE_SQL_SERVER", DEFAULT_SERVER)
    database = _setting("TE_PIE_SQL_DATABASE", DEFAULT_DATABASE)
    driver = _setting("TE_PIE_ODBC_DRIVER", "ODBC Driver 18 for SQL Server")
    connection_string = (
        f"Driver={{{driver}}};"
        f"Server={server};"
        f"Database={database};"
        "Trusted_Connection=yes;"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
        "Connection Timeout=20;"
    )
    return pyodbc.connect(connection_string, timeout=20)


def _rows_as_dicts(cursor):
    columns = [item[0] for item in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _find_project(project_key):
    """Return all tickets for an exact PROJECTKEY."""
    query = f"""
        SELECT
            [id], [ISSUEKEY], [PROJECTKEY], [PROJECTNAME], [summary], [status],
            [priority], [assignee], [reporter], [creator], [created], [updated],
            [duedate], [resolutiondate], [description], [Customer], [Impact],
            [Root Cause], [Root Cause Category], [Corrective Action],
            [Long Term Solution], [Key Updates], [Last Comment], [Test Stage],
            [MFG Engineer], [Mfg Test SW Engineer], [MFG Test SW TPM],
            [Quality Engineer], [System Engineer], [IT Engineer],
            [Infra IT Engineer], [Infra IT PM], [SS-Code], [SR-Code],
            [Snow Ticket], [Customer Ticket], [Rack SN], [Server SN],
            [Escalated], [Escalated Servers], [Escalated units], [On Hold],
            [Vendor RMA], [Tracking Number], [RTV Number], [SKU], [SKU Name],
            [C16B SKU/Component], [C2020 SKU/Component], [Impacted SS codes],
            [Error Message], [Location], [Work Type], [labels]
        FROM {_table_name()}
        WHERE UPPER(LTRIM(RTRIM(COALESCE([PROJECTKEY], '')))) = UPPER(?)
        ORDER BY [updated] DESC, [created] DESC, [id] DESC;
    """
    with closing(_connect()) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute(query, project_key)
            return _rows_as_dicts(cursor)


def _find_ticket(ticket_id):
    """Return every database field for one PIE ticket id."""
    query = f"SELECT TOP (1) * FROM {_table_name()} WHERE [id] = ?;"
    with closing(_connect()) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute(query, int(ticket_id))
            row = cursor.fetchone()
            if row is None:
                return None
            columns = [item[0] for item in cursor.description]
            return list(zip(columns, row))


def _get_current_week_open_tickets():
    """Return current-week PIE tickets whose status is not Closed."""
    query = f"""
        SET DATEFIRST 1;
        DECLARE @WeekStart date = DATEADD(day, 1 - DATEPART(weekday, GETDATE()), CAST(GETDATE() AS date));
        DECLARE @WeekEnd date = DATEADD(day, 7, @WeekStart);

        SELECT
            [id], [ISSUEKEY], [PROJECTKEY], [PROJECTNAME], [summary], [status],
            [priority], [assignee], [created], [updated], [duedate], [Customer],
            [Impact], [Test Stage], [MFG Engineer], [Quality Engineer],
            [System Engineer], [Location], [Escalated], [On Hold]
        FROM {_table_name()}
        WHERE [created] >= @WeekStart
          AND [created] < @WeekEnd
          AND LOWER(LTRIM(RTRIM(COALESCE([status], '')))) <> 'closed'
        ORDER BY
            CASE WHEN [duedate] IS NULL THEN 1 ELSE 0 END,
            [duedate] ASC, [updated] DESC, [created] DESC;
    """
    with closing(_connect()) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute(query)
            rows = _rows_as_dicts(cursor)

    status_counts = {}
    project_counts = {}
    assignees = set()
    for row in rows:
        status = str(row.get("status") or "Unspecified").strip() or "Unspecified"
        project = str(row.get("PROJECTKEY") or "No Project").strip() or "No Project"
        status_counts[status] = status_counts.get(status, 0) + 1
        project_counts[project] = project_counts.get(project, 0) + 1
        assignee = str(row.get("assignee") or "").strip()
        if assignee:
            assignees.add(assignee)
    return rows, status_counts, project_counts, len(assignees)


def register(app):
    if bp.name in app.blueprints:
        return
    core = __import__(app.import_name, fromlist=["section_required", "te_permission_required"])

    @bp.route("/te/pie-tickets", methods=["GET", "POST"])
    @core.section_required("te")
    @core.te_permission_required("te_pie_tickets")
    def index():
        project_key = (request.values.get("project_key") or "").strip()
        ticket_id = (request.values.get("ticket_id") or "").strip()
        project_results = []
        ticket = None
        searched = False
        error = None

        weekly_tickets = []
        weekly_status_counts = {}
        weekly_project_counts = {}
        weekly_assignee_count = 0
        weekly_error = None
        try:
            weekly_tickets, weekly_status_counts, weekly_project_counts, weekly_assignee_count = _get_current_week_open_tickets()
        except Exception as exc:
            weekly_error = str(exc)

        if ticket_id:
            if not ticket_id.isdigit():
                error = "Ticket id must contain numbers only."
            else:
                try:
                    ticket = _find_ticket(ticket_id)
                except Exception as exc:
                    error = str(exc)
        elif project_key:
            searched = True
            if not PROJECT_KEY_PATTERN.fullmatch(project_key):
                error = "PROJECTKEY may contain only letters, numbers, periods, underscores, and hyphens."
            else:
                try:
                    project_results = _find_project(project_key)
                except Exception as exc:
                    error = str(exc)

        return render_template(
            "te_pie_tickets/index.html",
            project_key=project_key,
            project_results=project_results,
            ticket=ticket,
            ticket_id=ticket_id,
            searched=searched,
            error=error,
            weekly_tickets=weekly_tickets,
            weekly_status_counts=weekly_status_counts,
            weekly_project_counts=weekly_project_counts,
            weekly_assignee_count=weekly_assignee_count,
            weekly_error=weekly_error,
        )

    app.register_blueprint(bp)
