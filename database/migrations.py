#!/usr/bin/env python3
"""
Database Migration System
Handles database schema changes and versioning
"""

import os
import sys
from datetime import datetime
from sqlalchemy import text

# Add the parent directory to the path so we can import our app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db

class DatabaseMigration:
    def __init__(self):
        self.migrations = []
        self._register_migrations()
    
    def _register_migrations(self):
        """Register all available migrations"""
        self.migrations = [
            {
                'version': 1,
                'name': 'Initial Schema',
                'description': 'Create initial database schema',
                'sql': '''
                -- This migration is handled by SQLAlchemy create_all()
                -- No manual SQL needed for initial schema
                '''
            },
            {
                'version': 2,
                'name': 'Add Indexes',
                'description': 'Add performance indexes to frequently queried columns',
                'sql': '''
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
                CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
                CREATE INDEX IF NOT EXISTS idx_events_start_date ON events(start_date);
                CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
                CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings(status);
                CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
                '''
            },
            {
                'version': 3,
                'name': 'Add Status to Events',
                'description': 'Add status column to events table',
                'sql': '''
                ALTER TABLE events ADD COLUMN status VARCHAR(20) DEFAULT 'active';
                CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
                '''
            },
            {
                'version': 4,
                'name': 'Add Verification Fields',
                'description': 'Add verification and active status fields',
                'sql': '''
                ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;
                ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE;
                ALTER TABLE ngos ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;
                CREATE INDEX IF NOT EXISTS idx_users_verified ON users(is_verified);
                CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
                CREATE INDEX IF NOT EXISTS idx_ngos_verified ON ngos(is_verified);
                '''
            }
        ]
    
    def get_current_version(self):
        """Get the current database version"""
        try:
            with app.app_context():
                # Check if migration table exists
                result = db.session.execute(text("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='migrations'
                """))
                
                if not result.fetchone():
                    # Create migrations table
                    db.session.execute(text("""
                        CREATE TABLE migrations (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            version INTEGER NOT NULL,
                            name VARCHAR(100) NOT NULL,
                            description TEXT,
                            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                    db.session.commit()
                    return 0
                
                # Get the latest version
                result = db.session.execute(text("""
                    SELECT MAX(version) as current_version FROM migrations
                """))
                row = result.fetchone()
                return row[0] if row[0] else 0
                
        except Exception as e:
            print(f"Error getting current version: {e}")
            return 0
    
    def apply_migration(self, migration):
        """Apply a single migration"""
        try:
            with app.app_context():
                print(f"Applying migration {migration['version']}: {migration['name']}")
                
                # Execute the migration SQL
                if migration['sql'].strip():
                    db.session.execute(text(migration['sql']))
                
                # Record the migration
                db.session.execute(text("""
                    INSERT INTO migrations (version, name, description)
                    VALUES (:version, :name, :description)
                """), {
                    'version': migration['version'],
                    'name': migration['name'],
                    'description': migration['description']
                })
                
                db.session.commit()
                print(f"✅ Migration {migration['version']} applied successfully")
                
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error applying migration {migration['version']}: {e}")
            raise
    
    def run_migrations(self):
        """Run all pending migrations"""
        current_version = self.get_current_version()
        print(f"Current database version: {current_version}")
        
        pending_migrations = [
            m for m in self.migrations 
            if m['version'] > current_version
        ]
        
        if not pending_migrations:
            print("✅ Database is up to date")
            return
        
        print(f"Found {len(pending_migrations)} pending migrations")
        
        for migration in sorted(pending_migrations, key=lambda x: x['version']):
            try:
                self.apply_migration(migration)
            except Exception as e:
                print(f"Migration failed: {e}")
                break
    
    def show_migrations(self):
        """Show all migrations and their status"""
        current_version = self.get_current_version()
        
        print("Migration Status:")
        print("=" * 60)
        
        for migration in self.migrations:
            status = "✅ Applied" if migration['version'] <= current_version else "⏳ Pending"
            print(f"{migration['version']:2d} | {status:10s} | {migration['name']}")
        
        print(f"\nCurrent version: {current_version}")
        print(f"Latest available version: {max(m['version'] for m in self.migrations)}")
    
    def reset_database(self):
        """Reset the database (DANGEROUS - removes all data)"""
        confirm = input("⚠️  This will delete ALL data. Are you sure? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Database reset cancelled")
            return
        
        try:
            with app.app_context():
                # Drop all tables
                db.drop_all()
                
                # Recreate tables
                db.create_all()
                
                # Reset migration table
                db.session.execute(text("DELETE FROM migrations"))
                db.session.commit()
                
                print("✅ Database reset successfully")
                
        except Exception as e:
            print(f"❌ Error resetting database: {e}")

def main():
    """Main function for running migrations"""
    migration_system = DatabaseMigration()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'status':
            migration_system.show_migrations()
        elif command == 'migrate':
            migration_system.run_migrations()
        elif command == 'reset':
            migration_system.reset_database()
        else:
            print("Unknown command. Use: status, migrate, or reset")
    else:
        # Default: run migrations
        migration_system.run_migrations()

if __name__ == '__main__':
    main()
