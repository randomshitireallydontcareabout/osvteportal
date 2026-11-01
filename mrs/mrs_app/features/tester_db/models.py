import sqlite3
import os

def init_tester_db(db_path=None):
    if not db_path:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        db_path = os.path.join(base_dir, "data", "mrs.db")
    
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tester_database (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tester_name TEXT NOT NULL,
            brand TEXT,
            component_type TEXT,
            stock_codes TEXT,
            os_version TEXT,
            bios_version TEXT,
            bmc_version TEXT,
            test_version TEXT,
            work_instruction TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()