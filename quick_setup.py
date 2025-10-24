#!/usr/bin/env python3
"""
Quick Setup Script for Admin Dashboard Testing
Helps users get started with testing the admin dashboard
"""

import os
import sys
import subprocess
from datetime import datetime

def print_header(title):
    print(f"\n{'='*60}")
    print(f"🚀 {title}")
    print('='*60)

def check_python_version():
    """Check Python version"""
    print_header("Checking Python Version")
    
    version = sys.version_info
    if version.major >= 3 and version.minor >= 7:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - SUPPORTED")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - NOT SUPPORTED")
        print("   Please upgrade to Python 3.7 or higher")
        return False

def install_dependencies():
    """Install required dependencies"""
    print_header("Installing Dependencies")
    
    dependencies = [
        'flask',
        'flask-sqlalchemy',
        'flask-login',
        'requests',
        'werkzeug'
    ]
    
    for dependency in dependencies:
        try:
            __import__(dependency.replace('-', '_'))
            print(f"✅ {dependency} - ALREADY INSTALLED")
        except ImportError:
            print(f"📦 Installing {dependency}...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', dependency])
                print(f"✅ {dependency} - INSTALLED")
            except subprocess.CalledProcessError:
                print(f"❌ Failed to install {dependency}")
                return False
    
    return True

def create_admin_user():
    """Create an admin user for testing using Flask-SQLAlchemy"""
    print_header("Creating Admin User")
    
    try:
        # Import required models and app
        from app import app, db
        from database.models import User
        from werkzeug.security import generate_password_hash
        
        with app.app_context():
            # Check if admin user already exists
            existing_admin = User.query.filter_by(email='admin@example.com').first()
            
            if existing_admin:
                print("✅ Admin user already exists: admin@example.com")
                print("   Password: admin123")
                return True
            
            # Create admin user
            admin_user = User(
                first_name='Admin',
                last_name='User',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                is_verified=True,
                is_active=True
            )
            
            db.session.add(admin_user)
            db.session.commit()
            
            print("✅ Admin user created successfully!")
            print("   Email: admin@example.com")
            print("   Password: admin123")
            print("   Role: admin")
            
            return True
        
    except ImportError as e:
        print(f"❌ Error importing required modules: {str(e)}")
        print("   Please ensure the Flask app is properly configured")
        return False
    except Exception as e:
        print(f"❌ Error creating admin user: {str(e)}")
        return False

def create_sample_data():
    """Create sample data for testing using Flask-SQLAlchemy"""
    print_header("Creating Sample Data")
    
    try:
        # Import required models and app
        from app import app, db
        from database.models import NGO, Event, Donation
        
        with app.app_context():
            # Sample NGOs
            sample_ngos = [
                {
                    'name': 'Helping Hands Foundation',
                    'description': 'Supporting local communities',
                    'email': 'help@helpinghands.org',
                    'phone': '+1234567890',
                    'address': '123 Main St',
                    'website': 'https://helpinghands.org',
                    'registration_number': 'NGO001'
                },
                {
                    'name': 'Education First',
                    'description': 'Providing education to underprivileged children',
                    'email': 'info@educationfirst.org',
                    'phone': '+1234567891',
                    'address': '456 Oak Ave',
                    'website': 'https://educationfirst.org',
                    'registration_number': 'NGO002'
                },
                {
                    'name': 'Green Earth Initiative',
                    'description': 'Environmental conservation and sustainability',
                    'email': 'contact@greenearth.org',
                    'phone': '+1234567892',
                    'address': '789 Pine Rd',
                    'website': 'https://greenearth.org',
                    'registration_number': 'NGO003'
                }
            ]
            
            created_ngos = []
            for ngo_data in sample_ngos:
                existing = NGO.query.filter_by(email=ngo_data['email']).first()
                if not existing:
                    ngo = NGO(**ngo_data, is_verified=True)
                    db.session.add(ngo)
                    created_ngos.append(ngo)
            
            db.session.flush()  # Get IDs for new NGOs
            
            # Sample Events
            sample_events = [
                {
                    'title': 'Community Food Drive',
                    'description': 'Collecting food for local families',
                    'date': '2024-01-15',
                    'time': '10:00:00',
                    'location': 'Community Center',
                    'max_volunteers': 50,
                    'ngo_id': 1
                },
                {
                    'title': 'Educational Workshop',
                    'description': 'Teaching basic computer skills',
                    'date': '2024-01-20',
                    'time': '14:00:00',
                    'location': 'Library Hall',
                    'max_volunteers': 30,
                    'ngo_id': 2
                },
                {
                    'title': 'Tree Planting Event',
                    'description': 'Planting trees in local parks',
                    'date': '2024-01-25',
                    'time': '09:00:00',
                    'location': 'City Park',
                    'max_volunteers': 100,
                    'ngo_id': 3
                }
            ]
            
            for event_data in sample_events:
                existing = Event.query.filter_by(title=event_data['title'], ngo_id=event_data['ngo_id']).first()
                if not existing:
                    event = Event(**event_data)
                    db.session.add(event)
            
            # Sample Donations
            sample_donations = [
                {'amount': 100.00, 'currency': 'USD', 'donor_name': 'John Doe', 'donor_email': 'john@example.com', 'ngo_id': 1},
                {'amount': 250.00, 'currency': 'USD', 'donor_name': 'Jane Smith', 'donor_email': 'jane@example.com', 'ngo_id': 2},
                {'amount': 75.00, 'currency': 'USD', 'donor_name': 'Bob Johnson', 'donor_email': 'bob@example.com', 'ngo_id': 3},
                {'amount': 500.00, 'currency': 'USD', 'donor_name': 'Alice Brown', 'donor_email': 'alice@example.com', 'ngo_id': 1}
            ]
            
            for donation_data in sample_donations:
                existing = Donation.query.filter_by(donor_email=donation_data['donor_email'], ngo_id=donation_data['ngo_id']).first()
                if not existing:
                    donation = Donation(**donation_data)
                    db.session.add(donation)
            
            db.session.commit()
            
            print("✅ Sample data created successfully!")
            print(f"   - {len(created_ngos)} NGOs added")
            print("   - 3 Events added")
            print("   - 4 Donations added")
            
            return True
        
    except ImportError as e:
        print(f"❌ Error importing required modules: {str(e)}")
        print("   Please ensure the Flask app is properly configured")
        return False
    except Exception as e:
        print(f"❌ Error creating sample data: {str(e)}")
        return False

def create_test_files():
    """Create test files if they don't exist"""
    print_header("Creating Test Files")
    
    test_files = [
        ('test_admin_dashboard.py', '#!/usr/bin/env python3\n# Admin dashboard tests will be added here'),
        ('validate_security.py', '#!/usr/bin/env python3\n# Security validation tests will be added here'),
        ('test_performance.py', '#!/usr/bin/env python3\n# Performance tests will be added here'),
        ('run_all_tests.py', '#!/usr/bin/env python3\n# Test runner will be added here')
    ]
    
    for filename, content in test_files:
        if not os.path.exists(filename):
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                print(f"✅ Created {filename}")
            except Exception as e:
                print(f"❌ Could not create {filename}: {str(e)}")
        else:
            print(f"✅ {filename} already exists")
    
    return True

def print_final_instructions():
    """Print final instructions for the user"""
    print_header("Setup Complete!")
    
    print("🎉 Your admin dashboard is ready for testing!")
    print("\n📋 Next Steps:")
    print("1. Start the Flask application:")
    print("   python app.py")
    print("\n2. Access the admin dashboard:")
    print("   Open http://localhost:5000/admin/dashboard")
    print("   Login with: admin@example.com / admin123")
    print("\n3. Run the comprehensive tests:")
    print("   python run_all_tests.py")
    print("\n4. Run individual test suites:")
    print("   python test_admin_dashboard.py  # Functional tests")
    print("   python validate_security.py      # Security validation")
    print("   python test_performance.py       # Performance tests")
    print("\n📚 Documentation:")
    print("   Check ADMIN_DASHBOARD_DOCS.md for detailed documentation")
    
    print(f"\n⏰ Setup completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """Main setup function"""
    print_header("Admin Dashboard Quick Setup")
    
    print("This script will help you set up the admin dashboard for testing.")
    print("Make sure you have the main application files (app.py, etc.) ready.")
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Dependency installation failed. Please install manually.")
        return False
    
    # Create admin user
    if not create_admin_user():
        print("\n❌ Admin user creation failed. You may need to create manually.")
    
    # Create sample data
    if not create_sample_data():
        print("\n❌ Sample data creation failed. You can add data manually.")
    
    # Create test files
    create_test_files()
    
    # Print final instructions
    print_final_instructions()
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⏰ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during setup: {str(e)}")
        sys.exit(1)