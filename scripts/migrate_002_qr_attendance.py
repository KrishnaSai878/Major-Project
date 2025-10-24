import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app
from database.models import db
from sqlalchemy import text

def table_exists(conn, name: str) -> bool:
    try:
        if conn.dialect.name == 'mysql':
            q = text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = :t")
            return (conn.execute(q, {"t": name}).scalar() or 0) > 0
        else:
            q = text("SELECT name FROM sqlite_master WHERE type='table' AND name = :t")
            return conn.execute(q, {"t": name}).fetchone() is not None
    except Exception:
        return False

def column_exists(conn, table: str, column: str) -> bool:
    try:
        if conn.dialect.name == 'mysql':
            q = text("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = :t AND column_name = :c")
            return (conn.execute(q, {"t": table, "c": column}).scalar() or 0) > 0
        else:
            # SQLite PRAGMA
            rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            return any(r[1] == column for r in rows)
    except Exception:
        return False

if __name__ == "__main__":
    with app.app_context():
        engine = db.engine
        with engine.begin() as conn:
            # Create attendance_tokens table if not exists
            if not table_exists(conn, 'attendance_tokens'):
                if conn.dialect.name == 'mysql':
                    conn.execute(text(
                        """
                        CREATE TABLE attendance_tokens (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            ngo_id INT NOT NULL,
                            event_id INT NOT NULL,
                            time_slot_id INT NULL,
                            token VARCHAR(64) NOT NULL UNIQUE,
                            expires_at DATETIME NOT NULL,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            is_active BOOLEAN DEFAULT TRUE,
                            INDEX idx_att_tok_ngo (ngo_id),
                            INDEX idx_att_tok_event (event_id),
                            INDEX idx_att_tok_slot (time_slot_id),
                            INDEX idx_att_tok_token (token),
                            INDEX idx_att_tok_expires (expires_at)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                        """
                    ))
                else:
                    conn.execute(text(
                        """
                        CREATE TABLE IF NOT EXISTS attendance_tokens (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ngo_id INTEGER NOT NULL,
                            event_id INTEGER NOT NULL,
                            time_slot_id INTEGER,
                            token TEXT NOT NULL UNIQUE,
                            expires_at DATETIME NOT NULL,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            is_active BOOLEAN DEFAULT 1
                        )
                        """
                    ))
                print("Created table attendance_tokens")
            else:
                print("Table attendance_tokens already exists")

            # Add attendance columns to bookings if missing
            for col, ddl_mysql, ddl_sqlite in [
                ("check_in_at", "ADD COLUMN check_in_at DATETIME NULL", "ADD COLUMN check_in_at DATETIME"),
                ("check_out_at", "ADD COLUMN check_out_at DATETIME NULL", "ADD COLUMN check_out_at DATETIME"),
                ("attendance_status", "ADD COLUMN attendance_status VARCHAR(20) DEFAULT 'pending'", "ADD COLUMN attendance_status TEXT")
            ]:
                if not column_exists(conn, 'bookings', col):
                    try:
                        if conn.dialect.name == 'mysql':
                            conn.execute(text(f"ALTER TABLE bookings {ddl_mysql}"))
                        else:
                            conn.execute(text(f"ALTER TABLE bookings {ddl_sqlite}"))
                        print(f"Added column bookings.{col}")
                    except Exception as e:
                        print(f"Could not add column {col}: {e}")
                else:
                    print(f"Column bookings.{col} already exists")
        print("Migration complete.")
