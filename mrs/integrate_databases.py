import sqlite3
import os

DB_PATH = os.path.join("data", "mrs.db")
STOCK_DB_PATH = "stockcode_products.db"
TESTER_DB_PATH = "tester.db"

def integrate_databases():
    print(f"Connecting to main database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Integrate stockcode_products.db
    if os.path.exists(STOCK_DB_PATH):
        print(f"Attaching {STOCK_DB_PATH}...")
        cursor.execute("ATTACH DATABASE ? AS stock_db", (STOCK_DB_PATH,))
        
        # Create table in mrs.db if missing
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stockcode_products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stock_code TEXT NOT NULL UNIQUE,
                brand TEXT,
                component_type TEXT,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1
            )
        """)
        
        # Copy data
        cursor.execute("""
            INSERT OR IGNORE INTO stockcode_products (stock_code, brand, component_type, description, created_at, updated_at, is_active)
            SELECT stock_code, brand, component_type, description, created_at, updated_at, is_active
            FROM stock_db.stockcode_products
        """)
        conn.commit()
        cursor.execute("DETACH DATABASE stock_db")
        print("Successfully integrated stockcode_products.db!")
    else:
        print(f"Warning: {STOCK_DB_PATH} not found in root directory.")

    # 2. Integrate tester.db
    if os.path.exists(TESTER_DB_PATH):
        print(f"Attaching {TESTER_DB_PATH}...")
        cursor.execute("ATTACH DATABASE ? AS tester_db", (TESTER_DB_PATH,))
        
        # Create testers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS testers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tester_name TEXT NOT NULL,
                brand TEXT,
                system TEXT,
                bios_firmware_version TEXT,
                bmc TEXT,
                tester_firmware_version TEXT,
                tests_for TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1
            )
        """)
        cursor.execute("""
            INSERT OR IGNORE INTO testers (id, tester_name, brand, system, bios_firmware_version, bmc, tester_firmware_version, tests_for, created_at, updated_at, is_active)
            SELECT id, tester_name, brand, system, bios_firmware_version, bmc, tester_firmware_version, tests_for, created_at, updated_at, is_active
            FROM tester_db.testers
        """)

        # Create tester_catalog table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tester_catalog (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tester_id INTEGER,
                tester_name TEXT NOT NULL,
                stock_code TEXT NOT NULL,
                part_description TEXT,
                part_type TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                UNIQUE(tester_name, stock_code)
            )
        """)
        cursor.execute("""
            INSERT OR IGNORE INTO tester_catalog (id, tester_id, tester_name, stock_code, part_description, part_type, created_at, updated_at, is_active)
            SELECT id, tester_id, tester_name, stock_code, part_description, part_type, created_at, updated_at, is_active
            FROM tester_db.tester_catalog
        """)

        # Create tester_maintenance table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tester_maintenance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tester_id INTEGER NOT NULL,
                maintenance_date TEXT NOT NULL,
                tester_name TEXT,
                stock_codes TEXT,
                brand TEXT,
                bios_firmware_version TEXT,
                bios_installed_date TEXT,
                bios_history TEXT,
                bmc_firmware_version TEXT,
                bmc_installed_date TEXT,
                bmc_history TEXT,
                script_version TEXT,
                script_installed_date TEXT,
                script_history TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1
            )
        """)
        cursor.execute("""
            INSERT OR IGNORE INTO tester_maintenance (id, tester_id, maintenance_date, tester_name, stock_codes, brand, bios_firmware_version, bios_installed_date, bios_history, bmc_firmware_version, bmc_installed_date, bmc_history, script_version, script_installed_date, script_history, notes, created_at, updated_at, is_active)
            SELECT id, tester_id, maintenance_date, tester_name, stock_codes, brand, bios_firmware_version, bios_installed_date, bios_history, bmc_firmware_version, bmc_installed_date, bmc_history, script_version, script_installed_date, script_history, notes, created_at, updated_at, is_active
            FROM tester_db.tester_maintenance
        """)

        conn.commit()
        cursor.execute("DETACH DATABASE tester_db")
        print("Successfully integrated tester.db!")
    else:
        print(f"Warning: {TESTER_DB_PATH} not found in root directory.")

    conn.close()
    print("Database integration complete.")

if __name__ == "__main__":
    integrate_databases()