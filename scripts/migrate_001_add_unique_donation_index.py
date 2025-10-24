import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app
from database.models import db
from sqlalchemy import text

"""
Adds a unique constraint/index on donations(network, tx_hash)
Safe to run multiple times.
Supports MySQL and SQLite fallback (no-op if already exists).
"""

def mysql_index_exists(conn, schema_name: str, index_name: str) -> bool:
    q = text(
        """
        SELECT COUNT(1) FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = :schema AND TABLE_NAME = 'donations' AND INDEX_NAME = :idx
        """
    )
    res = conn.execute(q, {"schema": schema_name, "idx": index_name}).scalar()
    return (res or 0) > 0

if __name__ == "__main__":
    with app.app_context():
        engine = db.engine
        try:
            url = str(engine.url)
            with engine.connect() as conn:
                if engine.dialect.name == 'mysql':
                    # Determine current database/schema
                    current_db = conn.execute(text("SELECT DATABASE()"))
                    schema = current_db.scalar() or ''
                    if not mysql_index_exists(conn, schema, 'uq_donations_network_tx'):
                        conn.execute(text("ALTER TABLE donations ADD CONSTRAINT uq_donations_network_tx UNIQUE (network, tx_hash)"))
                        print("Added unique constraint uq_donations_network_tx")
                    else:
                        print("Constraint/index uq_donations_network_tx already exists (MySQL)")
                else:
                    # Generic fallback: try create unique index, ignore if exists
                    try:
                        conn.execute(text("CREATE UNIQUE INDEX uq_donations_network_tx ON donations (network, tx_hash)"))
                        print("Created unique index uq_donations_network_tx (generic)")
                    except Exception as e:
                        print("Unique index likely exists or creation not supported:", str(e))
        except Exception as e:
            print("Migration failed:", str(e))
            raise
        print("Migration check complete.")
