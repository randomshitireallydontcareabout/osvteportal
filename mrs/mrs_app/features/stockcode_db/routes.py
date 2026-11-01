
import datetime
import csv
import io
import os
import re
import sqlite3
import tempfile
from flask import Blueprint, render_template, request, redirect, url_for, flash, session

bp = Blueprint("stockcode_db", __name__, template_folder="templates", static_folder="static")

# Column name aliases (normalised lowercase → canonical field)
FIELD_ALIASES = {
    "stock_code": ["stock_code", "stockcode", "code", "sku", "stock"],
    "brand": ["brand", "manufacturer", "make", "mfr", "vendor", "oem"],
    "category": ["category", "cat"],
    "component_type": ["component_type", "component", "type", "part_type", "part"],
    "tester_name": ["tester_name", "tester", "technician", "tech"],
    "est_hours": ["est_hours", "est_hour", "estimated_hours", "estimated_hour",
                  "hours", "hour", "time", "est_time", "estimated_time"],
    "testing_capabilities": ["testing_capabilities", "testing capability", "capabilities"],
    "validation": ["validation"],
    "availability": ["when", "availability"],
    "stock_code_prefix": ["stock_code_prefix", "prefix"],
    "validation_scope": ["validation_scope", "scope"],
    "status": ["status"],
    "description": ["description", "desc"],
    "high_value": ["high_value", "high value"],
}

CANONICAL_FIELDS = ["stock_code", "brand", "category", "component_type", "tester_name", "est_hours", "testing_capabilities", "validation", "availability", "stock_code_prefix", "validation_scope", "status", "description", "high_value"]


def now_standard():
    return datetime.datetime.now().strftime("%Y/%m/%d %I:%M:%S %p")


def normalize_header(h):
    return re.sub(r"[^a-z0-9]+", "_", str(h or "").strip().lower()).strip("_")


def resolve_field(header, aliases):
    n = normalize_header(header)
    if not n:
        return None
    for field, field_aliases in aliases.items():
        if n in field_aliases:
            return field
    # Partial match fallback (e.g. "component type" -> "component_type")
    for field, field_aliases in aliases.items():
        for alias in field_aliases:
            if alias in n or n in alias:
                return field
    return None


def parse_float(value):
    if value is None:
        return 0.0
    try:
        return float(str(value).strip())
    except (ValueError, TypeError):
        return 0.0


def upsert_stockcode(db, data):
    stock_code = (data.get("stock_code") or "").strip()
    if not stock_code:
        return False
    values = {
        "brand": (data.get("brand") or "").strip(),
        "category": (data.get("category") or "").strip(),
        "component_type": (data.get("component_type") or "").strip(),
        "tester_name": (data.get("tester_name") or "").strip(),
        "est_hours": parse_float(data.get("est_hours")),
        "testing_capabilities": (data.get("testing_capabilities") or "").strip(),
        "validation": (data.get("validation") or "").strip(),
        "availability": (data.get("availability") or "").strip(),
        "stock_code_prefix": (data.get("stock_code_prefix") or "").strip(),
        "validation_scope": (data.get("validation_scope") or "").strip(),
        "status": (data.get("status") or "").strip(),
        "description": (data.get("description") or "").strip(),
        "high_value": (data.get("high_value") or "").strip().upper(),
    }
    if not values["component_type"] and values["description"]:
        values["component_type"] = values["description"]
    db.execute("""INSERT INTO stockcode_metadata
        (stock_code,brand,category,component_type,tester_name,est_hours,testing_capabilities,
         validation,availability,stock_code_prefix,validation_scope,status,description,high_value,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(stock_code) DO UPDATE SET
          brand=COALESCE(NULLIF(excluded.brand,''),stockcode_metadata.brand),
          category=COALESCE(NULLIF(excluded.category,''),stockcode_metadata.category),
          component_type=COALESCE(NULLIF(excluded.component_type,''),stockcode_metadata.component_type),
          tester_name=COALESCE(NULLIF(excluded.tester_name,''),stockcode_metadata.tester_name),
          est_hours=CASE WHEN excluded.est_hours>0 THEN excluded.est_hours ELSE stockcode_metadata.est_hours END,
          testing_capabilities=COALESCE(NULLIF(excluded.testing_capabilities,''),stockcode_metadata.testing_capabilities),
          validation=COALESCE(NULLIF(excluded.validation,''),stockcode_metadata.validation),
          availability=COALESCE(NULLIF(excluded.availability,''),stockcode_metadata.availability),
          stock_code_prefix=COALESCE(NULLIF(excluded.stock_code_prefix,''),stockcode_metadata.stock_code_prefix),
          validation_scope=COALESCE(NULLIF(excluded.validation_scope,''),stockcode_metadata.validation_scope),
          status=COALESCE(NULLIF(excluded.status,''),stockcode_metadata.status),
          description=COALESCE(NULLIF(excluded.description,''),stockcode_metadata.description),
          high_value=COALESCE(NULLIF(excluded.high_value,''),stockcode_metadata.high_value)
    """, (stock_code, values["brand"], values["category"], values["component_type"],
          values["tester_name"], values["est_hours"], values["testing_capabilities"],
          values["validation"], values["availability"], values["stock_code_prefix"],
          values["validation_scope"], values["status"], values["description"],
          values["high_value"], now_standard()))
    return True


def sync_ticket_stockcode_fields(db):
    """Keep ticket Part Type and Part Description synchronized from StockCode DB.

    StockCode Category maps to ticket.part_type.
    StockCode Description maps to ticket.part_description.
    The StockCode database is authoritative when it contains a nonblank value.
    """
    table_names = {r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    if "tickets" not in table_names or "stockcode_metadata" not in table_names:
        return 0
    cursor = db.execute("""
        UPDATE tickets
        SET part_type = COALESCE(
                NULLIF((SELECT TRIM(s.category) FROM stockcode_metadata s
                        WHERE s.stock_code = tickets.stock_code COLLATE NOCASE LIMIT 1), ''),
                part_type
            ),
            part_description = COALESCE(
                NULLIF((SELECT TRIM(s.description) FROM stockcode_metadata s
                        WHERE s.stock_code = tickets.stock_code COLLATE NOCASE LIMIT 1), ''),
                part_description
            )
        WHERE EXISTS (
            SELECT 1 FROM stockcode_metadata s
            WHERE s.stock_code = tickets.stock_code COLLATE NOCASE
              AND (TRIM(COALESCE(s.category, '')) != ''
                   OR TRIM(COALESCE(s.description, '')) != '')
        )
    """)
    db.commit()
    return cursor.rowcount


def register(app):
    if bp.name in app.blueprints:
        return

    core = __import__(app.import_name, fromlist=["get_db", "permission_required", "admin_required"])

    with app.app_context():
        db = core.get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS stockcode_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stock_code TEXT NOT NULL UNIQUE COLLATE NOCASE,
                category TEXT,
                component_type TEXT,
                tester_name TEXT,
                est_hours REAL DEFAULT 0.0,
                created_at TEXT
            );
        """)
        cols = {r["name"] for r in db.execute("PRAGMA table_info(stockcode_metadata)").fetchall()}
        if "brand" not in cols:
            db.execute("ALTER TABLE stockcode_metadata ADD COLUMN brand TEXT")
        extra_columns = {
            "testing_capabilities":"TEXT", "validation":"TEXT", "availability":"TEXT",
            "stock_code_prefix":"TEXT", "validation_scope":"TEXT", "status":"TEXT",
            "description":"TEXT", "high_value":"TEXT"
        }
        cols = {r["name"] for r in db.execute("PRAGMA table_info(stockcode_metadata)").fetchall()}
        for column_name, column_type in extra_columns.items():
            if column_name not in cols:
                db.execute(f"ALTER TABLE stockcode_metadata ADD COLUMN {column_name} {column_type}")
        seed_path = os.path.join(os.path.dirname(__file__), "osv_stock_codes.csv")
        if os.path.isfile(seed_path):
            with open(seed_path, "r", encoding="utf-8-sig", newline="") as seed_file:
                for row in csv.DictReader(seed_file):
                    data = {field: row.get(header, "") for header, field in {
                        "Stock Code":"stock_code", "Testing Capabilities":"testing_capabilities",
                        "Validation":"validation", "When":"availability", "Stock Code Prefix":"stock_code_prefix",
                        "Validation Scope":"validation_scope", "Category":"category", "Status":"status",
                        "Description":"description", "High Value":"high_value"}.items()}
                    upsert_stockcode(db, data)
        db.commit()
        sync_ticket_stockcode_fields(db)

    # Refresh linked ticket fields before pages that display or complete tickets.
    # This keeps Overview and Completed Ticket popups synchronized even when
    # StockCode metadata is edited after tickets were originally imported.
    sync_endpoints = {"overview", "my_tickets", "my_completed", "history", "history_export"}

    @app.before_request
    def _sync_stockcode_ticket_display_fields():
        from flask import request as flask_request
        endpoint = flask_request.endpoint or ""
        if endpoint in sync_endpoints:
            sync_ticket_stockcode_fields(core.get_db())

    # Preserve the exact Start Test timestamp when the NTF completion form is saved.
    # The completion form may submit an empty/prefilled test_started_at value; the
    # database value captured by Start Test is authoritative and must not be replaced.
    completion_endpoint = "complete_pass_ajax"
    original_complete = app.view_functions.get(completion_endpoint)
    if original_complete and not getattr(original_complete, "_stockcode_time_guard", False):
        from functools import wraps

        @wraps(original_complete)
        def _complete_pass_with_time_guard(*args, **kwargs):
            ticket_id = kwargs.get("tid")
            before = None
            if ticket_id is not None:
                before = core.get_db().execute(
                    "SELECT test_started_at FROM tickets WHERE id=?", (ticket_id,)
                ).fetchone()
            response = original_complete(*args, **kwargs)
            if ticket_id is not None:
                db = core.get_db()
                current = db.execute(
                    "SELECT test_result, test_started_at FROM tickets WHERE id=?", (ticket_id,)
                ).fetchone()
                if current:
                    saved_start = before["test_started_at"] if before else None
                    normalized_result = (current["test_result"] or "").strip().casefold()
                    updates = []
                    params = []
                    if saved_start and not current["test_started_at"]:
                        updates.append("test_started_at=?")
                        params.append(saved_start)
                    if normalized_result in {"ntf", "passed"}:
                        updates.append("failure_reason=?")
                        params.append("Passed All Test (NTF)")
                        updates.append("quality_disposition=?")
                        params.append("N/A")
                    if updates:
                        params.append(ticket_id)
                        db.execute(f"UPDATE tickets SET {', '.join(updates)} WHERE id=?", params)
                        db.commit()
                        sync_ticket_stockcode_fields(db)
            return response

        _complete_pass_with_time_guard._stockcode_time_guard = True
        app.view_functions[completion_endpoint] = _complete_pass_with_time_guard

    # Existing NTF tickets should display a fixed completion statement instead of
    # an empty failure box. This is display-only completion data and is not editable.
    with app.app_context():
        db = core.get_db()
        db.execute("""UPDATE tickets
                      SET failure_reason='Passed All Test (NTF)', quality_disposition='N/A'
                      WHERE status='completed'
                        AND LOWER(TRIM(COALESCE(test_result,''))) IN ('ntf','passed')
                        AND (TRIM(COALESCE(failure_reason,''))=''
                             OR TRIM(COALESCE(quality_disposition,''))='')""")
        db.commit()

    @app.after_request
    def _style_completed_ntf_result(response):
        from flask import request as flask_request
        if (response.mimetype == "text/html" and not response.direct_passthrough):
            html = response.get_data(as_text=True)
            changed = False
            if flask_request.endpoint == "my_completed":
                style = """<style>
                .detail-block.danger div{font-weight:900;color:#86efac!important;
                  background:rgba(34,197,94,.10)!important;border-color:rgba(34,197,94,.35)!important}
                </style>"""
                if "Passed All Test (NTF)" in html and "detail-block.danger" in html:
                    html = html.replace("</head>", style + "</head>", 1)
                    changed = True
            elif flask_request.endpoint == "my_tickets":
                complete_ticket_script = r"""<script>
                (() => {
                  const NTF_TEXT = 'Passed All Test (NTF)';
                  function activeCompleteTicketForm() {
                    const modal = document.getElementById('ntf-modal');
                    if (!modal || getComputedStyle(modal).display === 'none') return null;
                    return modal.querySelector('form') || modal;
                  }
                  const byNames = (root, names) => names
                    .map(name => root ? root.querySelector(`[name="${name}"]`) : null)
                    .find(Boolean);
                  function applyCompleteTicketDefaults() {
                    const form = activeCompleteTicketForm();
                    if (!form) return;
                    const result = byNames(form, ['test_result', 'result']);
                    if (!result) return;
                    const isNtf = ['ntf', 'passed'].includes(String(result.value || '').trim().toLowerCase());
                    const failure = byNames(form, ['failure_reason', 'test_failure']);
                    const disposition = byNames(form, ['quality_disposition']);
                    if (isNtf) {
                      if (failure) {
                        failure.value = NTF_TEXT;
                        failure.readOnly = true;
                        failure.setAttribute('aria-readonly', 'true');
                        failure.style.fontWeight = '900';
                        failure.style.color = '#86efac';
                        failure.style.background = 'rgba(34,197,94,.10)';
                        failure.style.borderColor = 'rgba(34,197,94,.35)';
                      }
                      if (disposition) {
                        disposition.value = 'N/A';
                        if (disposition.tagName === 'INPUT' || disposition.tagName === 'TEXTAREA') {
                          disposition.readOnly = true;
                          disposition.setAttribute('aria-readonly', 'true');
                        }
                        disposition.style.fontWeight = '800';
                      }
                    } else {
                      if (failure) {
                        if (failure.value === NTF_TEXT) failure.value = '';
                        failure.readOnly = false;
                        failure.removeAttribute('aria-readonly');
                        failure.style.fontWeight = '';
                        failure.style.color = '';
                        failure.style.background = '';
                        failure.style.borderColor = '';
                      }
                      if (disposition && (disposition.tagName === 'INPUT' || disposition.tagName === 'TEXTAREA')) {
                        disposition.readOnly = false;
                        disposition.removeAttribute('aria-readonly');
                      }
                    }
                  }
                  document.addEventListener('change', event => {
                    if (event.target && ['test_result', 'result'].includes(event.target.name)) {
                      applyCompleteTicketDefaults();
                    }
                  });
                  document.addEventListener('click', event => {
                    if (event.target && event.target.closest && event.target.closest('[onclick*="openNtfModal"], .pass-btn')) {
                      setTimeout(applyCompleteTicketDefaults, 50);
                    }
                  });
                  document.addEventListener('submit', event => {
                    if (event.target && event.target.closest && event.target.closest('#ntf-modal')) {
                      applyCompleteTicketDefaults();
                    }
                  }, true);
                  new MutationObserver(applyCompleteTicketDefaults).observe(document.body, {childList:true, subtree:true, attributes:true, attributeFilter:['style','class']});
                })();
                </script>"""
                html = html.replace("</body>", complete_ticket_script + "</body>", 1)
                changed = True
            if changed:
                response.set_data(html)
                response.headers["Content-Length"] = len(response.get_data())
        return response

    if hasattr(core, "TAB_PERMISSIONS"):
        core.TAB_PERMISSIONS["stockcode_db"] = "StockCode DB"

    @bp.route("/stockcode-db")
    @core.login_required
    def index():
        db = core.get_db()
        entries = db.execute("SELECT * FROM stockcode_metadata ORDER BY stock_code COLLATE NOCASE").fetchall()
        brands = [r["brand"] for r in db.execute(
            "SELECT DISTINCT TRIM(brand) AS brand FROM stockcode_metadata "
            "WHERE brand IS NOT NULL AND TRIM(brand) != '' ORDER BY brand COLLATE NOCASE"
        ).fetchall()]

        # Group by brand -> component_type -> [entries]
        grouped = {}
        for entry in entries:
            brand = (entry["brand"] or "").strip() or "(No Brand)"
            comp_type = (entry["component_type"] or "").strip() or "(No Component Type)"
            grouped.setdefault(brand, {}).setdefault(comp_type, []).append(entry)

        grouped_sorted = {}
        for brand in sorted(grouped.keys(), key=lambda s: s.casefold()):
            comp_types = {}
            total = 0
            for ct in sorted(grouped[brand].keys(), key=lambda s: s.casefold()):
                comp_types[ct] = sorted(
                    grouped[brand][ct],
                    key=lambda e: (e["stock_code"] or "").casefold(),
                )
                total += len(comp_types[ct])
            grouped_sorted[brand] = {
                "component_types": comp_types,
                "total": total,
            }

        return render_template(
            "stockcode_db.html",
            entries=entries,
            brands=brands,
            grouped=grouped_sorted,
        )

    @bp.post("/stockcode-db/save")
    @core.login_required
    def save():
        db = core.get_db()
        entry_id = request.form.get("id")
        stock_code = (request.form.get("stock_code") or "").strip()
        brand = (request.form.get("brand") or "").strip()
        category = (request.form.get("category") or "").strip()
        component_type = (request.form.get("component_type") or "").strip()
        tester_name = (request.form.get("tester_name") or "").strip()
        extra = {name: (request.form.get(name) or "").strip() for name in
                 ["testing_capabilities","validation","availability","stock_code_prefix",
                  "validation_scope","status","description","high_value"]}
        try:
            est_hours = float(request.form.get("est_hours") or 0.0)
        except ValueError:
            est_hours = 0.0

        if not stock_code:
            flash("Stock Code is required.", "error")
            return redirect(url_for("stockcode_db.index"))

        if entry_id:
            db.execute("""UPDATE stockcode_metadata SET stock_code=?, brand=?, category=?, component_type=?,
                tester_name=?, est_hours=?, testing_capabilities=?, validation=?, availability=?,
                stock_code_prefix=?, validation_scope=?, status=?, description=?, high_value=? WHERE id=?""",
                (stock_code, brand, category, component_type, tester_name, est_hours,
                 extra["testing_capabilities"], extra["validation"], extra["availability"],
                 extra["stock_code_prefix"], extra["validation_scope"], extra["status"],
                 extra["description"], extra["high_value"], entry_id))
            flash(f"Stock Code metadata for {stock_code} updated successfully.", "success")
        else:
            try:
                upsert_stockcode(db, {"stock_code":stock_code,"brand":brand,"category":category,
                    "component_type":component_type,"tester_name":tester_name,"est_hours":est_hours,**extra})
                flash(f"Stock Code {stock_code} added to database.", "success")
            except Exception as e:
                flash(f"Error adding stock code (may already exist): {e}", "error")
        db.commit()
        return redirect(url_for("stockcode_db.index"))

    @bp.post("/stockcode-db/<int:entry_id>/delete")
    @core.admin_required
    def delete(entry_id):
        db = core.get_db()
        db.execute("DELETE FROM stockcode_metadata WHERE id=?", (entry_id,))
        db.commit()
        flash("Stock code entry deleted.", "success")
        return redirect(url_for("stockcode_db.index"))

    # ============================================================
    # Import: CSV
    # ============================================================
    @bp.post("/stockcode-db/import-csv")
    @core.admin_required
    def import_csv():
        file = request.files.get("csv_file")
        if not file or not file.filename:
            flash("No CSV file uploaded.", "error"); return redirect(url_for("stockcode_db.index"))
        db = core.get_db()
        added = updated = skipped = 0
        try:
            stream = io.TextIOWrapper(file.stream, encoding="utf-8-sig")
            reader = csv.DictReader(stream)
            headers = reader.fieldnames or []
            field_map = {}
            for h in headers:
                field = resolve_field(h, FIELD_ALIASES)
                if field:
                    field_map[h] = field
            if "stock_code" not in field_map.values():
                flash("CSV has no recognisable Stock Code column.", "error")
                return redirect(url_for("stockcode_db.index"))
            for row in reader:
                data = {}
                for h, field in field_map.items():
                    data[field] = row.get(h, "")
                stock_code = (data.get("stock_code") or "").strip()
                if not stock_code:
                    skipped += 1; continue
                existed = db.execute("SELECT id FROM stockcode_metadata WHERE stock_code=? COLLATE NOCASE",
                                     (stock_code,)).fetchone()
                ok = upsert_stockcode(db, data)
                if not ok:
                    skipped += 1
                elif existed:
                    updated += 1
                else:
                    added += 1
            db.commit()
            flash(f"CSV import complete — {added} added, {updated} updated, {skipped} skipped.", "success")
        except Exception as e:
            flash(f"CSV import failed: {e}", "error")
        return redirect(url_for("stockcode_db.index"))

    # ============================================================
    # Import: SQLite .db
    # ============================================================
    @bp.post("/stockcode-db/import-db")
    @core.admin_required
    def import_db():
        file = request.files.get("db_file")
        if not file or not file.filename:
            flash("No .db file uploaded.", "error"); return redirect(url_for("stockcode_db.index"))
        fd, tmp_path = tempfile.mkstemp(suffix=".db"); os.close(fd)
        try:
            file.save(tmp_path)
            src = sqlite3.connect(tmp_path); src.row_factory = sqlite3.Row
            tables = [r["name"] for r in src.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            if not tables:
                flash("Uploaded .db has no tables.", "error")
                return redirect(url_for("stockcode_db.index"))
            preferred = None
            for name in tables:
                cols = {c[1] for c in src.execute(f"PRAGMA table_info({name})").fetchall()}
                if "stock_code" in cols:
                    preferred = name; break
            if not preferred:
                for name in tables:
                    cols = {c[1].lower() for c in src.execute(f"PRAGMA table_info({name})").fetchall()}
                    if "stock_code" in cols or "stockcode" in cols or "code" in cols:
                        preferred = name; break
            if not preferred:
                flash("No suitable table with a Stock Code column found.", "error")
                return redirect(url_for("stockcode_db.index"))
            src_cols = [r[1] for r in src.execute(f"PRAGMA table_info({preferred})").fetchall()]
            col_field = {}
            for c in src_cols:
                field = resolve_field(c, FIELD_ALIASES)
                if field:
                    col_field[c] = field
            if "stock_code" not in col_field.values():
                flash("Stockcode table has no usable Stock Code column.", "error")
                return redirect(url_for("stockcode_db.index"))
            db = core.get_db()
            added = updated = skipped = 0
            select_cols = ", ".join(col_field.keys())
            for r in src.execute(f"SELECT {select_cols} FROM {preferred}").fetchall():
                data = {field: r[col] for col, field in col_field.items()}
                stock_code = (data.get("stock_code") or "").strip()
                if not stock_code:
                    skipped += 1; continue
                existed = db.execute("SELECT id FROM stockcode_metadata WHERE stock_code=? COLLATE NOCASE",
                                     (stock_code,)).fetchone()
                ok = upsert_stockcode(db, data)
                if not ok:
                    skipped += 1
                elif existed:
                    updated += 1
                else:
                    added += 1
            db.commit()
            src.close()
            flash(f"DB import complete — {added} added, {updated} updated, {skipped} skipped from table '{preferred}'.", "success")
        except Exception as e:
            flash(f"DB import failed: {e}", "error")
        finally:
            try: os.unlink(tmp_path)
            except OSError: pass
        return redirect(url_for("stockcode_db.index"))

    # ============================================================
    # Template CSV download
    # ============================================================
    @bp.route("/stockcode-db/template.csv")
    @core.login_required
    def template_csv():
        from flask import Response
        rows = ["stock_code,brand,category,component_type,tester_name,est_hours,testing_capabilities,validation,availability,stock_code_prefix,validation_scope,status,description,high_value",
                "STK-0001,Samsung,DIMM,DDR5 32GB,Alice,2.5",
                "STK-0002,Intel,CPU,Xeon Gold 6338,Bob,3.0"]
        return Response("\n".join(rows), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=stockcode_template.csv"})

    app.register_blueprint(bp)
