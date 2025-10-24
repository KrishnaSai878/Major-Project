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
                -- Skip if indexes already exist (MySQL doesn't have IF NOT EXISTS for CREATE INDEX)
                -- These indexes might already exist from SQLAlchemy auto-creation
                '''
            },
            {
                'version': 3,
                'name': 'Add Status to Events',
                'description': 'Add status column to events table',
                'sql': '''
                -- Add status column only if it doesn\'t exist
                SET @dbname = DATABASE();
                SET @tablename = 'events';
                SET @columnname = 'status';
                SET @preparedStatement = (SELECT IF(
                  (
                    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE
                      (TABLE_NAME = @tablename)
                      AND (TABLE_SCHEMA = @dbname)
                      AND (COLUMN_NAME = @columnname)
                  ) > 0,
                  'SELECT 1',
                  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' VARCHAR(20) DEFAULT \'active\';')
                ));
                PREPARE alterIfNotExists FROM @preparedStatement;
                EXECUTE alterIfNotExists;
                DEALLOCATE PREPARE alterIfNotExists;
                '''
            },
            {
                'version': 4,
                'name': 'Add Verification Fields',
                'description': 'Add verification and active status fields',
                'sql': '''
                -- Add verification fields only if they don\'t exist
                SET @dbname = DATABASE();
                
                -- Add is_verified to users
                SET @tablename = 'users';
                SET @columnname = 'is_verified';
                SET @preparedStatement = (SELECT IF(
                  (
                    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE
                      (TABLE_NAME = @tablename)
                      AND (TABLE_SCHEMA = @dbname)
                      AND (COLUMN_NAME = @columnname)
                  ) > 0,
                  'SELECT 1',
                  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' BOOLEAN DEFAULT FALSE;')
                ));
                PREPARE alterIfNotExists FROM @preparedStatement;
                EXECUTE alterIfNotExists;
                DEALLOCATE PREPARE alterIfNotExists;
                
                -- Add is_active to users
                SET @columnname = 'is_active';
                SET @preparedStatement = (SELECT IF(
                  (
                    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE
                      (TABLE_NAME = @tablename)
                      AND (TABLE_SCHEMA = @dbname)
                      AND (COLUMN_NAME = @columnname)
                  ) > 0,
                  'SELECT 1',
                  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' BOOLEAN DEFAULT TRUE;')
                ));
                PREPARE alterIfNotExists FROM @preparedStatement;
                EXECUTE alterIfNotExists;
                DEALLOCATE PREPARE alterIfNotExists;
                
                -- Add is_verified to ngos
                SET @tablename = 'ngos';
                SET @columnname = 'is_verified';
                SET @preparedStatement = (SELECT IF(
                  (
                    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE
                      (TABLE_NAME = @tablename)
                      AND (TABLE_SCHEMA = @dbname)
                      AND (COLUMN_NAME = @columnname)
                  ) > 0,
                  'SELECT 1',
                  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' BOOLEAN DEFAULT FALSE;')
                ));
                PREPARE alterIfNotExists FROM @preparedStatement;
                EXECUTE alterIfNotExists;
                DEALLOCATE PREPARE alterIfNotExists;
                '''
            },
            {
                'version': 5,
                'name': 'Add NGO Email Column',
                'description': 'Add email column to ngos table',
                'sql': '''
                -- Add email column only if it doesn\'t exist
                SET @dbname = DATABASE();
                SET @tablename = 'ngos';
                SET @columnname = 'email';
                SET @preparedStatement = (SELECT IF(
                  (
                    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE
                      (TABLE_NAME = @tablename)
                      AND (TABLE_SCHEMA = @dbname)
                      AND (COLUMN_NAME = @columnname)
                  ) > 0,
                  'SELECT 1',
                  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' VARCHAR(120);')
                ));
                PREPARE alterIfNotExists FROM @preparedStatement;
                EXECUTE alterIfNotExists;
                DEALLOCATE PREPARE alterIfNotExists;
                '''
            },
            {
                'version': 6,
                'name': 'Add Established Year to NGOs',
                'description': 'Add established_year column to ngos table',
                'sql': '''
                -- Add established_year column only if it doesn\'t exist
                SET @dbname = DATABASE();
                SET @tablename = 'ngos';
                SET @columnname = 'established_year';
                SET @preparedStatement = (SELECT IF(
                  (
                    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE
                      (TABLE_NAME = @tablename)
                      AND (TABLE_SCHEMA = @dbname)
                      AND (COLUMN_NAME = @columnname)
                  ) > 0,
                  'SELECT 1',
                  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' INT;')
                ));
                PREPARE alterIfNotExists FROM @preparedStatement;
                EXECUTE alterIfNotExists;
                DEALLOCATE PREPARE alterIfNotExists;
                '''
            }
        ]
    
    def get_current_version(self):
        """Get the current database version"""
        try:
            with app.app_context():
                # Check if migration table exists
                result = db.session.execute(text("""
                    SELECT COUNT(*) FROM information_schema.tables 
                    WHERE table_schema = DATABASE() AND table_name = 'migrations'
                """))
                
                if result.fetchone()[0] == 0:
                    # Create migrations table
                    db.session.execute(text("""
                        CREATE TABLE migrations (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            version INT NOT NULL,
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
    
    def column_exists(self, table_name, column_name):
        """Check if a column exists in a table"""
        try:
            result = db.session.execute(text("""
                SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = :table_name
                AND COLUMN_NAME = :column_name
            """), {'table_name': table_name, 'column_name': column_name})
            return result.fetchone()[0] > 0
        except:
            return False
    
    def apply_migration(self, migration):
        """Apply a single migration"""
        try:
            with app.app_context():
                print(f"Applying migration {migration['version']}: {migration['name']}")
                
                # Handle specific migrations with conditional logic
                if migration['version'] == 3:
                    # Add status column to events if it doesn't exist
                    if not self.column_exists('events', 'status'):
                        db.session.execute(text("ALTER TABLE events ADD COLUMN status VARCHAR(20) DEFAULT 'active'"))
                        print("  Added status column to events table")
                    else:
                        print("  Status column already exists in events table")
                
                elif migration['version'] == 4:
                    # Add verification fields
                    if not self.column_exists('users', 'is_verified'):
                        db.session.execute(text("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE"))
                        print("  Added is_verified column to users table")
                    
                    if not self.column_exists('users', 'is_active'):
                        db.session.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE"))
                        print("  Added is_active column to users table")
                    
                    if not self.column_exists('ngos', 'is_verified'):
                        db.session.execute(text("ALTER TABLE ngos ADD COLUMN is_verified BOOLEAN DEFAULT FALSE"))
                        print("  Added is_verified column to ngos table")
                
                elif migration['version'] == 5:
                    # Add email column to ngos if it doesn't exist
                    if not self.column_exists('ngos', 'email'):
                        db.session.execute(text("ALTER TABLE ngos ADD COLUMN email VARCHAR(120)"))
                        print("  Added email column to ngos table")
                    else:
                        print("  Email column already exists in ngos table")
                
                elif migration['version'] == 6:
                    # Add established_year column to ngos if it doesn't exist
                    if not self.column_exists('ngos', 'established_year'):
                        db.session.execute(text("ALTER TABLE ngos ADD COLUMN established_year INT"))
                        print("  Added established_year column to ngos table")
                    else:
                        print("  Established year column already exists in ngos table")
                
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
        with app.app_context():
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






