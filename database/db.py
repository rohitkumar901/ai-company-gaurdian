import sqlite3
import hashlib
from typing import Optional
from config import DATABASE_PATH, DEFAULT_SETTINGS

def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Return a configured SQLite connection with row factory enabled."""
    target_path = db_path or str(DATABASE_PATH)
    conn = sqlite3.connect(target_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def hash_password(password: str) -> str:
    """Secure SHA-256 with project salt for demonstration and prototype security."""
    salt = "guardian_secure_salt_2026"
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()

def init_db(db_path: Optional[str] = None) -> None:
    """Initialize database tables, indexes, default admin/analyst users and system settings."""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 1. Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'analyst')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Import jobs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS import_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        total_rows INTEGER NOT NULL,
        valid_rows INTEGER NOT NULL,
        invalid_rows INTEGER DEFAULT 0,
        duplicate_rows INTEGER DEFAULT 0,
        uploaded_by TEXT NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Security events table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        import_job_id INTEGER REFERENCES import_jobs(id) ON DELETE SET NULL,
        timestamp TIMESTAMP NOT NULL,
        username TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        login_result TEXT NOT NULL CHECK(login_result IN ('SUCCESS', 'FAILURE')),
        event_type TEXT DEFAULT 'LOGIN',
        device_info TEXT DEFAULT 'Standard Browser',
        country_code TEXT DEFAULT 'US',
        hour_of_day INTEGER,
        day_of_week INTEGER,
        is_off_hours BOOLEAN DEFAULT 0,
        event_hash TEXT UNIQUE
    );
    """)

    # 4. Alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT UNIQUE NOT NULL,
        event_id INTEGER REFERENCES security_events(id) ON DELETE CASCADE,
        username TEXT NOT NULL,
        detection_rule TEXT NOT NULL,
        detection_method TEXT NOT NULL CHECK(detection_method IN ('RULE', 'ML', 'HYBRID')),
        severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
        anomaly_score REAL DEFAULT NULL,
        reason TEXT NOT NULL,
        status TEXT DEFAULT 'New' CHECK(status IN ('New', 'Investigating', 'Resolved', 'False Positive')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 5. Investigation notes table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigation_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
        analyst_username TEXT NOT NULL,
        note TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 6. Audit history table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        target_id TEXT,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 7. System settings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT NOT NULL,
        description TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Helpful Indexes for speed
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_user_time ON security_events(username, timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip_time ON security_events(ip_address, timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(username);")

    # Seed Default Users if empty
    cursor.execute("SELECT COUNT(*) FROM users;")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);",
            ("admin", hash_password("Admin@Guardian2026"), "admin")
        )
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?);",
            ("analyst", hash_password("Analyst@Guardian2026"), "analyst")
        )

    # Seed Default Settings if empty
    cursor.execute("SELECT COUNT(*) FROM system_settings;")
    if cursor.fetchone()[0] == 0:
        for k, v in DEFAULT_SETTINGS.items():
            cursor.execute(
                "INSERT OR IGNORE INTO system_settings (setting_key, setting_value, description) VALUES (?, ?, ?);",
                (k, str(v), f"System configuration for {k}")
            )

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at", DATABASE_PATH)
