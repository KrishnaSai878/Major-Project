#!/usr/bin/env python3
"""
Database Initialization Script
Creates database tables and populates with sample data
"""

import os
import sys
import json
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

# Add the parent directory to the path so we can import our app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from database.models import User, NGO, Volunteer, Donor, Event, TimeSlot, Booking, Message, Resource, Project

def create_sample_data():
    """Create sample data for the database"""
    
    # Create admin user
    admin_user = User(
        email='admin@ngoconnect.com',
        password_hash=generate_password_hash('admin123'),
        role='admin',
        first_name='Admin',
        last_name='User',
        phone='1234567890',
        is_verified=True,
        is_active=True
    )
    db.session.add(admin_user)
    
    # Create NGO users and organizations
    ngo_users = []
    ngo_organizations = [
        {
            'name': 'Green Earth Foundation',
            'description': 'Environmental conservation and sustainability',
            'mission': 'To protect and preserve our environment for future generations',
            'category': 'Environment',
            'city': 'New York',
            'state': 'NY'
        },
        {
            'name': 'Hope for Children',
            'description': 'Supporting underprivileged children',
            'mission': 'Providing education and care for children in need',
            'category': 'Education',
            'city': 'Los Angeles',
            'state': 'CA'
        },
        {
            'name': 'Community Health Initiative',
            'description': 'Improving community health and wellness',
            'mission': 'Making healthcare accessible to all communities',
            'category': 'Healthcare',
            'city': 'Chicago',
            'state': 'IL'
        }
    ]
    
    for i, org in enumerate(ngo_organizations):
        user = User(
            email=f'ngo{i+1}@example.com',
            password_hash=generate_password_hash('ngo123'),
            role='ngo',
            first_name=f'NGO{i+1}',
            last_name='Manager',
            phone=f'555-{1000+i}',
            is_verified=True,
            is_active=True
        )
        db.session.add(user)
        db.session.flush()  # Get the user ID
        
        ngo = NGO(
            user_id=user.id,
            organization_name=org['name'],
            description=org['description'],
            mission=org['mission'],
            website=f'https://{org["name"].lower().replace(" ", "")}.org',
            address=f'{100+i} Main St',
            city=org['city'],
            state=org['state'],
            zip_code=f'{10000+i}',
            email=f'contact@{org["name"].lower().replace(" ", "")}.org',
            category=org['category'],
            established_year=2010 + i,
            is_verified=True
        )
        db.session.add(ngo)
        ngo_users.append(user)
    
    # Create volunteer users
    volunteer_users = []
    volunteer_data = [
        {'name': 'John', 'surname': 'Smith', 'skills': ['Teaching', 'Mentoring', 'Event Planning'], 'interests': ['Education', 'Youth Development']},
        {'name': 'Sarah', 'surname': 'Johnson', 'skills': ['Medical', 'First Aid', 'Counseling'], 'interests': ['Healthcare', 'Mental Health']},
        {'name': 'Mike', 'surname': 'Brown', 'skills': ['Construction', 'Handyman', 'Team Leadership'], 'interests': ['Community Development', 'Infrastructure']},
        {'name': 'Emily', 'surname': 'Davis', 'skills': ['Marketing', 'Social Media', 'Fundraising'], 'interests': ['Non-profit', 'Social Causes']},
        {'name': 'David', 'surname': 'Wilson', 'skills': ['IT Support', 'Web Development', 'Data Analysis'], 'interests': ['Technology', 'Education']}
    ]
    
    for i, vol_data in enumerate(volunteer_data):
        user = User(
            email=f'volunteer{i+1}@example.com',
            password_hash=generate_password_hash('vol123'),
            role='volunteer',
            first_name=vol_data['name'],
            last_name=vol_data['surname'],
            phone=f'555-{3000+i}',
            is_verified=True,
            is_active=True
        )
        db.session.add(user)
        db.session.flush()
        
        volunteer = Volunteer(
            user_id=user.id,
            bio=f'Passionate volunteer with experience in {", ".join(vol_data["interests"])}',
            skills=json.dumps(vol_data['skills']),
            interests=json.dumps(vol_data['interests']),
            availability=json.dumps({
                'monday': ['09:00-12:00', '14:00-17:00'],
                'tuesday': ['09:00-12:00', '14:00-17:00'],
                'wednesday': ['09:00-12:00', '14:00-17:00'],
                'thursday': ['09:00-12:00', '14:00-17:00'],
                'friday': ['09:00-12:00', '14:00-17:00'],
                'saturday': ['10:00-15:00'],
                'sunday': ['10:00-15:00']
            }),
            total_hours=20 + (i * 5),
            total_points=100 + (i * 25)
        )
        db.session.add(volunteer)
        volunteer_users.append(user)
    
    # Create donor users
    donor_users = []
    donor_data = [
        {'name': 'Alice', 'surname': 'Thompson', 'company': 'TechCorp Inc'},
        {'name': 'Robert', 'surname': 'Garcia', 'company': 'Global Solutions Ltd'},
        {'name': 'Lisa', 'surname': 'Anderson', 'company': 'Community Bank'}
    ]
    
    for i, donor_info in enumerate(donor_data):
        user = User(
            email=f'donor{i+1}@example.com',
            password_hash=generate_password_hash('donor123'),
            role='donor',
            first_name=donor_info['name'],
            last_name=donor_info['surname'],
            phone=f'555-{4000+i}',
            is_verified=True,
            is_active=True
        )
        db.session.add(user)
        db.session.flush()
        
        donor = Donor(
            user_id=user.id,
            company_name=donor_info['company'],
            donation_history=json.dumps([
                {'amount': 5000, 'date': '2024-01-15', 'organization': 'Green Earth Foundation'},
                {'amount': 3000, 'date': '2024-02-20', 'organization': 'Hope for Children'}
            ]),
            preferences=json.dumps({
                'categories': ['Education', 'Environment'],
                'min_amount': 1000,
                'max_amount': 10000
            })
        )
        db.session.add(donor)
        donor_users.append(user)
    
    db.session.commit()
    
    # Create events
    events = []
    event_data = [
        {
            'title': 'Tree Planting Day',
            'description': 'Join us for a community tree planting event',
            'category': 'Environment',
            'ngo_index': 0,
            'start_date': datetime.now() + timedelta(days=7),
            'end_date': datetime.now() + timedelta(days=7, hours=4),
            'max_volunteers': 20,
            'required_skills': ['Physical Labor', 'Teamwork']
        },
        {
            'title': 'Children\'s Reading Program',
            'description': 'Help children improve their reading skills',
            'category': 'Education',
            'ngo_index': 1,
            'start_date': datetime.now() + timedelta(days=3),
            'end_date': datetime.now() + timedelta(days=3, hours=3),
            'max_volunteers': 15,
            'required_skills': ['Teaching', 'Patience', 'Communication']
        },
        {
            'title': 'Health Awareness Workshop',
            'description': 'Conduct health awareness sessions in communities',
            'category': 'Healthcare',
            'ngo_index': 2,
            'start_date': datetime.now() + timedelta(days=5),
            'end_date': datetime.now() + timedelta(days=5, hours=2),
            'max_volunteers': 10,
            'required_skills': ['Medical Knowledge', 'Public Speaking']
        }
    ]
    
    for event_info in event_data:
        ngo = NGO.query.filter_by(organization_name=ngo_organizations[event_info['ngo_index']]['name']).first()
        event = Event(
            ngo_id=ngo.id,
            title=event_info['title'],
            description=event_info['description'],
            location=f'{ngo.city}, {ngo.state}',
            start_date=event_info['start_date'],
            end_date=event_info['end_date'],
            max_volunteers=event_info['max_volunteers'],
            required_skills=json.dumps(event_info['required_skills']),
            category=event_info['category'],
            status='active'
        )
        db.session.add(event)
        db.session.flush()
        events.append(event)
        
        # Create time slots for each event
        for i in range(3):  # 3 time slots per event
            start_time = event_info['start_date'] + timedelta(hours=i)
            end_time = start_time + timedelta(hours=2)
            
            time_slot = TimeSlot(
                event_id=event.id,
                start_time=start_time,
                end_time=end_time,
                max_volunteers=5,
                current_volunteers=0,
                is_available=True
            )
            db.session.add(time_slot)
    
    # Create some bookings
    for i, event in enumerate(events):
        if i < len(volunteer_users):
            volunteer = Volunteer.query.filter_by(user_id=volunteer_users[i].id).first()
            time_slot = TimeSlot.query.filter_by(event_id=event.id).first()
            
            if volunteer and time_slot:
                booking = Booking(
                    volunteer_id=volunteer.id,
                    time_slot_id=time_slot.id,
                    event_id=event.id,
                    status='confirmed',
                    hours_worked=2.0,
                    points_earned=20
                )
                db.session.add(booking)
                
                # Update time slot
                time_slot.current_volunteers += 1
                if time_slot.current_volunteers >= time_slot.max_volunteers:
                    time_slot.is_available = False
    
    # Create some messages
    for i in range(5):
        sender = volunteer_users[i % len(volunteer_users)]
        receiver = ngo_users[i % len(ngo_users)]
        
        message = Message(
            sender_id=sender.id,
            receiver_id=receiver.id,
            content=f'Sample message {i+1} from {sender.first_name} to {receiver.first_name}',
            is_read=False
        )
        db.session.add(message)
    
    # Create some resources
    for i, ngo in enumerate(NGO.query.all()):
        resource = Resource(
            ngo_id=ngo.id,
            title=f'Sample Resource {i+1}',
            description=f'This is a sample resource for {ngo.organization_name}',
            file_path=f'/uploads/resource_{i+1}.pdf',
            file_type='pdf',
            is_public=True
        )
        db.session.add(resource)
    
    # Create some projects
    for i, ngo in enumerate(NGO.query.all()):
        project = Project(
            ngo_id=ngo.id,
            title=f'Sample Project {i+1}',
            description=f'This is a sample project for {ngo.organization_name}',
            status='active',
            start_date=datetime.now() - timedelta(days=30),
            end_date=datetime.now() + timedelta(days=60)
        )
        db.session.add(project)
    
    db.session.commit()
    print("✅ Sample data created successfully!")

def init_database():
    """Initialize the database with tables and sample data"""
    print("🗄️  Initializing database...")
    
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✅ Database tables created successfully!")
        
        # Check if we already have data
        if User.query.count() == 0:
            print("📝 Creating sample data...")
            create_sample_data()
        else:
            print("ℹ️  Database already contains data, skipping sample data creation")

if __name__ == '__main__':
    init_database()






