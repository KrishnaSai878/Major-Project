#!/usr/bin/env python3
"""
NGO Connect Platform Startup Script
This script helps you quickly set up and run the NGO Connect platform.
"""

import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required.")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")

def create_env_file():
    """Create .env file if it doesn't exist."""
    env_file = Path('.env')
    if not env_file.exists():
        print("📝 Creating .env file...")
        env_content = """# NGO Connect Platform Environment Variables

# Flask Configuration
SECRET_KEY=your-super-secret-key-change-this-in-production
FLASK_ENV=development
DEBUG=True

# Database Configuration
SQLALCHEMY_DATABASE_URI=sqlite:///ngo_connect.db
SQLALCHEMY_TRACK_MODIFICATIONS=False

# Email Configuration (optional - update if you want email features)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# File Upload Configuration
UPLOAD_FOLDER=static/uploads
MAX_CONTENT_LENGTH=16777216

# Client URL (for CORS)
CLIENT_URL=http://localhost:3000
"""
        with open(env_file, 'w') as f:
            f.write(env_content)
        print("✅ .env file created successfully!")
        print("⚠️  Please update the email configuration in .env if you want to use email features.")
    else:
        print("✅ .env file already exists")

def install_dependencies():
    """Install Python dependencies."""
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully!")
    except subprocess.CalledProcessError:
        print("❌ Error installing dependencies. Please run: pip install -r requirements.txt")
        sys.exit(1)

def create_upload_folder():
    """Create upload folder if it doesn't exist."""
    upload_folder = Path('static/uploads')
    upload_folder.mkdir(parents=True, exist_ok=True)
    print("✅ Upload folder created")

def run_migrations():
    """Run database migrations."""
    print("🗄️  Setting up database...")
    try:
        from app import app, db
        with app.app_context():
            db.create_all()
        print("✅ Database initialized successfully!")
    except Exception as e:
        print(f"❌ Error setting up database: {e}")
        sys.exit(1)

def start_server():
    """Start the Flask development server."""
    print("🚀 Starting NGO Connect Platform...")
    print("📍 Server will be available at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop the server")
    print("-" * 50)
    
    try:
        from app import app, socketio
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n👋 Server stopped. Goodbye!")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

def main():
    """Main function to set up and run the platform."""
    print("🌟 NGO Connect Platform Setup")
    print("=" * 40)
    
    # Check Python version
    check_python_version()
    
    # Create .env file
    create_env_file()
    
    # Install dependencies
    install_dependencies()
    
    # Create upload folder
    create_upload_folder()
    
    # Run migrations
    run_migrations()
    
    # Start server
    start_server()

if __name__ == '__main__':
    main()
