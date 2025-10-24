import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app
from database.models import db

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("DB tables ensured (created if missing)")
