import csv
import io
import os
import re
import sqlite3
import tempfile
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, current_app

tester_db_bp = Blueprint('tester_db', __name__, template_folder='templates', static_folder='static')

TESTER_FIELD_ALIASES = {
    "tester_name": ["tester_name", "tester", "name", "technician", "tech"],
    "brand": ["brand", "manufacturer", "make", "vendor"],
    "component_type": ["component_type", "component", "type", "part_type"],
    "stock_codes": ["stock_codes", "stock_code", "codes", "supported_codes"],
    "os_version": ["os_version", "os", "operating_system"],
    "bios_version": ["bios_version", "bios", "firmware"],
    "bmc_version": ["bmc_version", "bmc"],
    "test_version": ["test_version", "test", "version"],
    "work_instruction": ["work_instruction", "instructions", "wi", "guide"],
}


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db_path = current_app.config.get('DATABASE', 'data/mrs.db')
        db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
        g._database = db
    return db


def _normalize_header(h):
    return re.sub(r"[^a-z0-9]+", "_", str(h or "").strip().lower()).strip("_")


def _resolve_field(header):
    n = _normalize_header(header)
    if not n:
        return None
    for field, aliases in TESTER_FIELD_ALIASES.items():
        if n in aliases:
            return field
    for field, aliases in TESTER_FIELD_ALIASES.items():
        for alias in aliases:
            if alias in n or n in alias:
                return field
    return None


def _upsert_tester(db, data):
    tester_name = (data.get("tester_name") or "").strip()
    if not tester_name:
        return False
    existing = db.execute("SELECT id FROM tester_database WHERE tester_name=? COLLATE NOCASE",
                          (tester_name,)).fetchone()
    fields = ["brand", "component_type", "stock_codes", "os_version",
              "bios_version", "bmc_version", "test_version", "work_instruction"]
    values = {f: (data.get(f) or "").strip() for f in fields}
    if existing:
        db.execute("""UPDATE tester_database SET brand=COALESCE(NULLIF(?,''),brand),
            component_type=COALESCE(NULLIF(?,''),component_type),
            stock_codes=COALESCE(NULLIF(?,''),stock_codes),
            os_version=COALESCE(NULLIF(?,''),os_version),
            bios_version=COALESCE(NULLIF(?,''),bios_version),
            bmc_version=COALESCE(NULLIF(?,''),bmc_version),
            test_version=COALESCE(NULLIF(?,''),test_version),
            work_instruction=COALESCE(NULLIF(?,''),work_instruction)
            WHERE id=?""",
            (values["brand"], values["component_type"], values["stock_codes"],
             values["os_version"], values["bios_version"], values["bmc_version"],
             values["test_version"], values["work_instruction"], existing["id"]))
        return "updated"
    db.execute("""INSERT INTO tester_database
        (tester_name, brand, component_type, stock_codes, os_version, bios_version,
         bmc_version, test_version, work_instruction)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (tester_name, values["brand"], values["component_type"], values["stock_codes"],
         values["os_version"], values["bios_version"], values["bmc_version"],
         values["test_version"], values["work_instruction"]))
    return "added"


@tester_db_bp.route('/tester-db', methods=['GET', 'POST'])
def index():
    db = get_db()

    if request.method == 'POST':
        tester_name = request.form.get('tester_name', '').strip()
        brand = request.form.get('brand', '').strip()
        component_type = request.form.get('component_type', '').strip()
        stock_codes_raw = request.form.getlist('stock_codes[]')
        stock_codes = [s.strip() for s in stock_codes_raw if s and s.strip()]
        stock_codes_str = ", ".join(stock_codes)
        os_version = request.form.get('os_version', '').strip()
        bios_version = request.form.get('bios_version', '').strip()
        bmc_version = request.form.get('bmc_version', '').strip()
        test_version = request.form.get('test_version', '').strip()
        work_instruction = request.form.get('work_instruction', '').strip()

        if tester_name:
            db.execute("""
                INSERT INTO tester_database (tester_name, brand, component_type, stock_codes, os_version, bios_version, bmc_version, test_version, work_instruction)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tester_name, brand, component_type, stock_codes_str, os_version, bios_version, bmc_version, test_version, work_instruction))
            db.commit()
            flash('Tester configuration added successfully!', 'success')
        else:
            flash('Tester name is required.', 'danger')
        return redirect(url_for('tester_db.index'))

    search_query = request.args.get('q', '').strip()
    if search_query:
        query = """
            SELECT * FROM tester_database
            WHERE tester_name LIKE ? OR brand LIKE ? OR component_type LIKE ? OR stock_codes LIKE ?
            ORDER BY id DESC
        """
        like_q = f"%{search_query}%"
        rows = [dict(r) for r in db.execute(query, (like_q, like_q, like_q, like_q)).fetchall()]
    else:
        rows = [dict(r) for r in db.execute("SELECT * FROM tester_database ORDER BY id DESC").fetchall()]

    return render_template('tester_db/index.html', testers=rows, search_query=search_query)


@tester_db_bp.route('/tester-db/edit/<int:id>', methods=['POST'])
def edit(id):
    db = get_db()
    tester_name = request.form.get('tester_name', '').strip()
    brand = request.form.get('brand', '').strip()
    component_type = request.form.get('component_type', '').strip()
    stock_codes_raw = request.form.getlist('stock_codes[]')
    stock_codes = [s.strip() for s in stock_codes_raw if s and s.strip()]
    stock_codes_str = ", ".join(stock_codes)
    os_version = request.form.get('os_version', '').strip()
    bios_version = request.form.get('bios_version', '').strip()
    bmc_version = request.form.get('bmc_version', '').strip()
    test_version = request.form.get('test_version', '').strip()
    work_instruction = request.form.get('work_instruction', '').strip()

    if tester_name:
        db.execute("""
            UPDATE tester_database
            SET tester_name=?, brand=?, component_type=?, stock_codes=?, os_version=?, bios_version=?, bmc_version=?, test_version=?, work_instruction=?
            WHERE id=?
        """, (tester_name, brand, component_type, stock_codes_str, os_version, bios_version, bmc_version, test_version, work_instruction, id))
        db.commit()
        flash('Tester configuration updated successfully!', 'success')
    else:
        flash('Tester name is required.', 'danger')
    return redirect(url_for('tester_db.index'))


@tester_db_bp.route('/tester-db/delete/<int:id>', methods=['POST'])
def delete(id):
    db = get_db()
    db.execute("DELETE FROM tester_database WHERE id=?", (id,))
    db.commit()
    flash('Tester configuration deleted.', 'info')
    return redirect(url_for('tester_db.index'))


# ============================================================
# Import: CSV
# ============================================================
@tester_db_bp.route('/tester-db/import-csv', methods=['POST'])
def import_csv():
    file = request.files.get('csv_file')
    if not file or not file.filename:
        flash('No CSV file uploaded.', 'danger'); return redirect(url_for('tester_db.index'))
    db = get_db()
    added = updated = skipped = 0
    try:
        stream = io.TextIOWrapper(file.stream, encoding='utf-8-sig')
        reader = csv.DictReader(stream)
        headers = reader.fieldnames or []
        field_map = {}
        for h in headers:
            field = _resolve_field(h)
            if field:
                field_map[h] = field
        if 'tester_name' not in field_map.values():
            flash('CSV has no recognisable Tester Name column.', 'danger')
            return redirect(url_for('tester_db.index'))
        for row in reader:
            data = {field: row.get(h, '') for h, field in field_map.items()}
            result = _upsert_tester(db, data)
            if result == 'added': added += 1
            elif result == 'updated': updated += 1
            else: skipped += 1
        db.commit()
        flash(f'CSV import complete — {added} added, {updated} updated, {skipped} skipped.', 'success')
    except Exception as e:
        flash(f'CSV import failed: {e}', 'danger')
    return redirect(url_for('tester_db.index'))


# ============================================================
# Import: SQLite .db
# ============================================================
@tester_db_bp.route('/tester-db/import-db', methods=['POST'])
def import_db():
    file = request.files.get('db_file')
    if not file or not file.filename:
        flash('No .db file uploaded.', 'danger'); return redirect(url_for('tester_db.index'))
    fd, tmp_path = tempfile.mkstemp(suffix='.db'); os.close(fd)
    try:
        file.save(tmp_path)
        src = sqlite3.connect(tmp_path); src.row_factory = sqlite3.Row
        tables = [r['name'] for r in src.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        if not tables:
            flash('Uploaded .db has no tables.', 'danger'); return redirect(url_for('tester_db.index'))
        preferred = None
        for name in tables:
            cols = {c[1].lower() for c in src.execute(f"PRAGMA table_info({name})").fetchall()}
            if 'tester_name' in cols or 'tester' in cols:
                preferred = name; break
        if not preferred:
            preferred = tables[0]
        src_cols = [r[1] for r in src.execute(f"PRAGMA table_info({preferred})").fetchall()]
        col_field = {}
        for c in src_cols:
            field = _resolve_field(c)
            if field:
                col_field[c] = field
        if 'tester_name' not in col_field.values():
            flash(f"Table '{preferred}' has no usable Tester Name column.", 'danger')
            return redirect(url_for('tester_db.index'))
        db = get_db()
        added = updated = skipped = 0
        select_cols = ", ".join(col_field.keys())
        for r in src.execute(f"SELECT {select_cols} FROM {preferred}").fetchall():
            data = {field: r[col] for col, field in col_field.items()}
            result = _upsert_tester(db, data)
            if result == 'added': added += 1
            elif result == 'updated': updated += 1
            else: skipped += 1
        db.commit(); src.close()
        flash(f"DB import complete — {added} added, {updated} updated, {skipped} skipped from table '{preferred}'.", 'success')
    except Exception as e:
        flash(f'DB import failed: {e}', 'danger')
    finally:
        try: os.unlink(tmp_path)
        except OSError: pass
    return redirect(url_for('tester_db.index'))


# ============================================================
# Template CSV download
# ============================================================
@tester_db_bp.route('/tester-db/template.csv')
def template_csv():
    from flask import Response
    rows = ["tester_name,brand,component_type,stock_codes,os_version,bios_version,bmc_version,test_version,work_instruction",
            "Supermicro-Test-01,Supermicro,Motherboard,\"STK-0001, STK-0002\",Ubuntu 22.04,v1.2.4,v2.10,v3.4.1,C:\\WI\\smc.pdf"]
    return Response("\n".join(rows), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=tester_template.csv'})