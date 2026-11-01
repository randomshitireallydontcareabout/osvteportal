#!/usr/bin/env python3
"""
integrate_osv.py - Script to import and sync OSV Tracker CSV data into the SQLite database.
"""

import os
import sys
import sqlite3
import pandas as pd
from datetime import datetime

# Default configuration paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "tickets.db")
CSV_PATH = os.path.join(BASE_DIR, "OSV Tracker List.csv")

# Expected columns to add to sqlite table if they don't exist
REQUIRED_COLUMNS = {
    "wh_location": "TEXT",
    "part_type": "TEXT",
    "quality_disposition": "TEXT",
    "bb_flag": "INTEGER DEFAULT 0",
    "sxm1_flag": "INTEGER DEFAULT 0",
    "serial_number": "TEXT",
    "part_number": "TEXT",
    "vendor": "TEXT",
    "osv_status": "TEXT"
}

def ensure_schema_extensions(conn):
    """Dynamically updates sqlite schema if new fields are required."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(tickets);")
    existing_cols = {col[1] for col in cursor.fetchall()}
    
    for col_name, col_type in REQUIRED_COLUMNS.items():
        if col_name not in existing_cols:
            print(f"Adding missing column '{col_name}' to 'tickets' table...")
            cursor.execute(f"ALTER TABLE tickets ADD COLUMN {col_name} {col_type};")
            
    conn.commit()

def clean_value(val, default=""):
    """Helper to handle pandas NaN / null values cleanly."""
    if pd.isna(val) or val is None:
        return default
    return str(val).strip()

def import_osv_csv(csv_path=CSV_PATH, db_path=DB_PATH):
    """Reads OSV CSV tracker and upserts records into the SQLite tickets table."""
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at '{csv_path}'")
        sys.exit(1)
        
    if not os.path.exists(db_path):
        print(f"Warning: SQLite database not found at '{db_path}'. A new database will be initialized.")

    conn = sqlite3.connect(db_path)
    ensure_schema_extensions(conn)
    cursor = conn.cursor()

    print(f"Reading CSV data from: {csv_path}")
    # Read CSV, handling common delimiter/encoding variations
    df = pd.read_csv(csv_path, dtype=str)
    
    # Normalize column headers for easier matching (strip whitespace, lowercase)
    df.columns = [c.strip() for c in df.columns]

    imported_count = 0
    updated_count = 0

    for idx, row in df.iterrows():
        # Flexibly match common CSV column naming conventions
        ticket_id = clean_value(row.get("Ticket ID") or row.get("Ticket") or row.get("ID"))
        title = clean_value(row.get("Title") or row.get("Description") or row.get("Summary"), "OSV Import Entry")
        status = clean_value(row.get("Status") or row.get("OSV Status"), "Closed")
        wh_location = clean_value(row.get("WH Location") or row.get("Location") or row.get("Warehouse"))
        part_type = clean_value(row.get("Part Type") or row.get("Type") or row.get("Stock Code"))
        serial_number = clean_value(row.get("Part SN") or row.get("Serial Number") or row.get("SN"))
        part_number = clean_value(row.get("Part Number") or row.get("PN") or row.get("Part #"))
        vendor = clean_value(row.get("Vendor") or row.get("Manufacturer"))
        quality_disp = clean_value(row.get("Quality Disposition") or row.get("Disposition"))
        
        # Flags check
        bb_flag = 1 if clean_value(row.get("BB Flag")).lower() in ['1', 'true', 'yes'] else 0
        sxm1_flag = 1 if clean_value(row.get("SXM1 Flag")).lower() in ['1', 'true', 'yes'] else 0

        now = datetime.utcnow().isoformat()

        if ticket_id:
            # Check if ticket already exists
            cursor.execute("SELECT id FROM tickets WHERE id = ?", (ticket_id,))
            exists = cursor.fetchone()

            if exists:
                cursor.execute("""
                    UPDATE tickets SET
                        title = COALESCE(NULLIF(?, ''), title),
                        status = COALESCE(NULLIF(?, ''), status),
                        wh_location = ?,
                        part_type = ?,
                        serial_number = ?,
                        part_number = ?,
                        vendor = ?,
                        quality_disposition = ?,
                        bb_flag = ?,
                        sxm1_flag = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (title, status, wh_location, part_type, serial_number, part_number, vendor, quality_disp, bb_flag, sxm1_flag, now, ticket_id))
                updated_count += 1
            else:
                cursor.execute("""
                    INSERT INTO tickets (
                        id, title, status, wh_location, part_type, 
                        serial_number, part_number, vendor, quality_disposition, 
                        bb_flag, sxm1_flag, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (ticket_id, title, status, wh_location, part_type, serial_number, part_number, vendor, quality_disp, bb_flag, sxm1_flag, now, now))
                imported_count += 1
        else:
            # Insert without explicit ID (autoincrement if supported)
            cursor.execute("""
                INSERT INTO tickets (
                    title, status, wh_location, part_type, 
                    serial_number, part_number, vendor, quality_disposition, 
                    bb_flag, sxm1_flag, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (title, status, wh_location, part_type, serial_number, part_number, vendor, quality_disp, bb_flag, sxm1_flag, now, now))
            imported_count += 1

    conn.commit()
    conn.close()

    print(f"\nImport finished successfully!")
    print(f" - New records added: {imported_count}")
    print(f" - Existing records updated: {updated_count}")

if __name__ == "__main__":
    import_osv_csv()