import sqlite3
import pandas as pd
import os

DB_PATH = "mrs.db"
CSV_PATH = "OSV Tracker List.csv"

def integrate_osv_database():
    print(f"Connecting to database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Ensure all columns exist in the tickets table
    new_columns = [
        ("wh_location", "TEXT"),
        ("part_type", "TEXT"),
        ("part_description", "TEXT"),
        ("return_time", "TEXT"),
        ("quality_disposition", "TEXT"),
        ("logs_uploaded", "TEXT"),
        ("log_path", "TEXT"),
        ("stock_cd", "TEXT"),
        ("bb_flag", "INTEGER"),
        ("sxm1_flag", "INTEGER"),
        ("sxm2_flag", "INTEGER"),
        ("sxm3_flag", "INTEGER"),
        ("sxm4_flag", "INTEGER"),
        ("sxm5_flag", "INTEGER"),
        ("sxm6_flag", "INTEGER"),
        ("sxm7_flag", "INTEGER"),
        ("sxm8_flag", "INTEGER"),
        ("csv_id", "INTEGER"),
        ("csv_index", "TEXT"),
        ("modified", "TEXT")
    ]

    existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(tickets)").fetchall()}
    
    for col_name, col_type in new_columns:
        if col_name not in existing_cols:
            print(f"Adding missing column: {col_name} ({col_type})")
            cursor.execute(f"ALTER TABLE tickets ADD COLUMN {col_name} {col_type}")

    conn.commit()

    # 2. Load OSV Tracker List CSV
    print(f"Loading CSV from {CSV_PATH}...")
    df = pd.read_csv(CSV_PATH)
    print(f"Loaded {len(df)} rows from CSV.")

    # 3. Insert / Import records into tickets table
    imported_count = 0
    for _, row in df.iterrows():
        cursor.execute("""
            INSERT INTO tickets (
                stock_code, mrs_ticket, status, assigned_at, completed_at, created_at,
                technician_name, test_started_at, test_result, failure_reason,
                mrs_comments, serial_number, wh_location, part_type, part_description,
                return_time, quality_disposition, logs_uploaded, log_path,
                stock_cd, bb_flag, sxm1_flag, sxm2_flag, sxm3_flag, sxm4_flag,
                sxm5_flag, sxm6_flag, sxm7_flag, sxm8_flag, csv_id, csv_index, modified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(row.get('Stock Code', '')) if pd.notna(row.get('Stock Code')) else '',
            str(row.get('Title', '')) if pd.notna(row.get('Title')) else '',
            'completed', # Default status for historical records in OSV tracker
            str(row.get('Assigned Time', '')) if pd.notna(row.get('Assigned Time')) else None,
            str(row.get('Test End Time', '')) if pd.notna(row.get('Test End Time')) else None,
            str(row.get('Assigned Time', '')) if pd.notna(row.get('Assigned Time')) else '2025/04/01 12:00:00 AM',
            str(row.get('Technician', '')) if pd.notna(row.get('Technician')) else None,
            str(row.get('Test Start Time', '')) if pd.notna(row.get('Test Start Time')) else None,
            str(row.get('Result', '')) if pd.notna(row.get('Result')) else None,
            str(row.get('Test Failure', '')) if pd.notna(row.get('Test Failure')) else None,
            str(row.get('Comments', '')) if pd.notna(row.get('Comments')) else None,
            str(row.get('Part SN', '')) if pd.notna(row.get('Part SN')) else None,
            str(row.get('WH Location', '')) if pd.notna(row.get('WH Location')) else None,
            str(row.get('Part Type', '')) if pd.notna(row.get('Part Type')) else None,
            str(row.get('Part Description', '')) if pd.notna(row.get('Part Description')) else None,
            str(row.get('Return Time', '')) if pd.notna(row.get('Return Time')) else None,
            str(row.get('Quality Disposition', '')) if pd.notna(row.get('Quality Disposition')) else None,
            str(row.get('Logs Uploaded', '')) if pd.notna(row.get('Logs Uploaded')) else None,
            str(row.get('Log Path', '')) if pd.notna(row.get('Log Path')) else None,
            str(row.get('Stock_cd', '')) if pd.notna(row.get('Stock_cd')) else None,
            int(row.get('BB Flag', 0)) if pd.notna(row.get('BB Flag')) else 0,
            int(row.get('SXM1 Flag', 0)) if pd.notna(row.get('SXM1 Flag')) else 0,
            int(row.get('SXM2 Flag', 0)) if pd.notna(row.get('SXM2 Flag')) else 0,
            int(row.get('SXM3 Flag', 0)) if pd.notna(row.get('SXM3 Flag')) else 0,
            int(row.get('SXM4 Flag', 0)) if pd.notna(row.get('SXM4 Flag')) else 0,
            int(row.get('SXM5 Flag', 0)) if pd.notna(row.get('SXM5 Flag')) else 0,
            int(row.get('SXM6 Flag', 0)) if pd.notna(row.get('SXM6 Flag')) else 0,
            int(row.get('SXM7 Flag', 0)) if pd.notna(row.get('SXM7 Flag')) else 0,
            int(row.get('SXM8 Flag', 0)) if pd.notna(row.get('SXM8 Flag')) else 0,
            int(row.get('ID', 0)) if pd.notna(row.get('ID')) else 0,
            str(row.get('Index', '')) if pd.notna(row.get('Index')) else None,
            str(row.get('Modified', '')) if pd.notna(row.get('Modified')) else None
        ))
        imported_count += 1

    conn.commit()
    conn.close()
    print(f"Successfully integrated database! Imported {imported_count} records into {DB_PATH}.")

if __name__ == '__main__':
    integrate_osv_database()