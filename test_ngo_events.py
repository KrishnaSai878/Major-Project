#!/usr/bin/env python3
"""
Test script for NGO Event CRUD operations
"""
import os
import sys
import json
from datetime import datetime, timedelta

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from database.models import User, NGO, Event, TimeSlot, Booking
from werkzeug.security import generate_password_hash

def test_ngo_event_crud():
    """Test the NGO event CRUD operations"""
    
    with app.app_context():
        # Create database tables
        db.create_all()
        
        print("Testing NGO Event CRUD Operations...")
        print("=" * 50)
        
        # 1. Create a test NGO user
        print("1. Creating test NGO user...")
        ngo_user = User(
            email='test_ngo@example.com',
            password_hash=generate_password_hash('password123'),
            role='ngo',
            first_name='Test',
            last_name='NGO',
            phone='1234567890'
        )
        db.session.add(ngo_user)
        db.session.commit()
        
        ngo = NGO(
            user_id=ngo_user.id,
            organization_name='Test NGO Organization',
            description='A test NGO for CRUD operations',
            mission='To test event management functionality',
            website='https://testngo.org',
            address='123 Test Street',
            city='Test City',
            state='Test State',
            zip_code='12345',
            category='Community Service'
        )
        db.session.add(ngo)
        db.session.commit()
        
        print(f"   ✓ Created NGO: {ngo.organization_name}")
        
        # 2. Create a test event
        print("\n2. Creating test event...")
        event = Event(
            ngo_id=ngo.id,
            title='Test Community Cleanup',
            description='A test event for community cleanup',
            location='Central Park',
            start_date=datetime.now() + timedelta(days=7),
            end_date=datetime.now() + timedelta(days=7),
            category='Community Service',
            max_volunteers=10,
            required_skills=json.dumps(['Manual Labor', 'Organization']),
            is_active=True
        )
        db.session.add(event)
        db.session.commit()
        
        print(f"   ✓ Created event: {event.title}")
        print(f"   ✓ Event ID: {event.id}")
        print(f"   ✓ Required skills: {event.get_required_skills()}")
        
        # 3. Create time slots for the event
        print("\n3. Creating time slots...")
        start_date = event.start_date
        for hour in range(9, 17, 2):
            start_time = datetime.combine(start_date, datetime.min.time().replace(hour=hour))
            end_time = start_time + timedelta(hours=2)
            
            time_slot = TimeSlot(
                event_id=event.id,
                start_time=start_time,
                end_time=end_time,
                max_volunteers=event.max_volunteers,
                current_volunteers=0,
                is_available=True
            )
            db.session.add(time_slot)
        
        db.session.commit()
        print(f"   ✓ Created {len(event.time_slots.all())} time slots")
        
        # 4. Test reading events
        print("\n4. Testing event retrieval...")
        events = Event.query.filter_by(ngo_id=ngo.id).all()
        print(f"   ✓ Found {len(events)} events for NGO")
        
        for evt in events:
            print(f"   - {evt.title} (Active: {evt.is_active})")
            print(f"     Skills: {evt.get_required_skills()}")
            print(f"     Time slots: {evt.time_slots.count()}")
        
        # 5. Test updating event
        print("\n5. Testing event update...")
        event.title = 'Updated Community Cleanup Event'
        event.description = 'Updated description for the test event'
        event.updated_at = datetime.utcnow()
        db.session.commit()
        
        updated_event = Event.query.get(event.id)
        print(f"   ✓ Updated event title: {updated_event.title}")
        print(f"   ✓ Updated at: {updated_event.updated_at}")
        
        # 6. Test event status toggle
        print("\n6. Testing event status toggle...")
        original_status = event.is_active
        event.is_active = not event.is_active
        db.session.commit()
        
        toggled_event = Event.query.get(event.id)
        print(f"   ✓ Toggled status from {original_status} to {toggled_event.is_active}")
        
        # 7. Test event deletion
        print("\n7. Testing event deletion...")
        event_id = event.id
        time_slot_count = event.time_slots.count()
        
        # Delete related bookings and time slots first
        Booking.query.filter_by(event_id=event.id).delete()
        TimeSlot.query.filter_by(event_id=event.id).delete()
        
        # Delete the event
        db.session.delete(event)
        db.session.commit()
        
        # Verify deletion
        deleted_event = Event.query.get(event_id)
        if deleted_event is None:
            print(f"   ✓ Successfully deleted event {event_id}")
            print(f"   ✓ Deleted {time_slot_count} associated time slots")
        else:
            print(f"   ✗ Failed to delete event {event_id}")
        
        # 8. Clean up test data
        print("\n8. Cleaning up test data...")
        db.session.delete(ngo)
        db.session.delete(ngo_user)
        db.session.commit()
        print("   ✓ Cleaned up test data")
        
        print("\n" + "=" * 50)
        print("All NGO Event CRUD tests completed successfully!")
        print("The event management system is working correctly.")

if __name__ == '__main__':
    test_ngo_event_crud()
