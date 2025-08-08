#!/usr/bin/env python3
"""
Seed the database with sample users, NGOs, volunteers, events, time slots, and bookings.
Run: python -m database.seed
"""

from datetime import datetime, timedelta, time
import json
import random

from .models import db, User, NGO, Volunteer, Donor, Event, TimeSlot, Booking


def create_user(email, role, first_name, last_name, password_hash):
    user = User(
        email=email,
        role=role,
        first_name=first_name,
        last_name=last_name,
        password_hash=password_hash,
        is_verified=True,
        created_at=datetime.utcnow(),
    )
    db.session.add(user)
    db.session.flush()
    return user


def create_sample_data():
    # Basic password hash for all demo users
    # Note: In the app real flow, we use werkzeug generate_password_hash. For seed, store plain for simplicity if needed.
    # Prefer importing from werkzeug, but to keep this module standalone avoid extra deps; tests will login via forms anyway.
    from werkzeug.security import generate_password_hash
    pw_hash = generate_password_hash("password123")

    # Admin
    if not User.query.filter_by(email="admin@example.com").first():
        create_user("admin@example.com", "admin", "Admin", "User", pw_hash)

    # NGOs
    ngo_users = []
    ngo_specs = [
        ("care@edu.org", "Bright Education", "Education", "Hyderabad"),
        ("heal@health.org", "Health First", "Healthcare", "Mumbai"),
        ("green@earth.org", "Green Earth", "Environment", "Bengaluru"),
    ]
    for email, org_name, category, city in ngo_specs:
        existing = User.query.filter_by(email=email).first()
        if existing:
            ngo_user = existing
        else:
            ngo_user = create_user(email, "ngo", org_name.split()[0], "Lead", pw_hash)
        ngo_users.append((ngo_user, org_name, category, city))

    ngos = []
    for user, org_name, category, city in ngo_users:
        ngo = NGO.query.filter_by(user_id=user.id).first()
        if not ngo:
            ngo = NGO(
                user_id=user.id,
                organization_name=org_name,
                description=f"{org_name} focuses on {category.lower()} initiatives.",
                mission=f"Advance {category.lower()} across communities.",
                website="https://example.org",
                city=city,
                state="Telangana" if city == "Hyderabad" else "Maharashtra" if city == "Mumbai" else "Karnataka",
                category=category,
                is_verified=True,
                created_at=datetime.utcnow(),
            )
            db.session.add(ngo)
        ngos.append(ngo)

    # Volunteers
    vol_specs = [
        ("ali@vol.org", "Ali", "Khan", ["Teaching", "Mentoring"], ["Education"]),
        ("sita@vol.org", "Sita", "Rao", ["First Aid", "Coordination"], ["Healthcare", "Community Service"]),
        ("rahul@vol.org", "Rahul", "Verma", ["Planting", "Waste Management"], ["Environment"]),
    ]
    volunteers = []
    for email, first_name, last_name, skills, interests in vol_specs:
        user = User.query.filter_by(email=email).first()
        if not user:
            user = create_user(email, "volunteer", first_name, last_name, pw_hash)
        vol = Volunteer.query.filter_by(user_id=user.id).first()
        if not vol:
            vol = Volunteer(
                user_id=user.id,
                bio=f"Volunteer {first_name} {last_name}",
                skills=json.dumps(skills),
                interests=json.dumps(interests),
                total_hours=0,
                total_points=0,
                created_at=datetime.utcnow(),
            )
            db.session.add(vol)
        volunteers.append(vol)

    db.session.flush()

    # Events and time slots for each NGO
    categories = ["Education", "Healthcare", "Environment", "Community Service"]
    for ngo in ngos:
        for i in range(2):
            start_day = datetime.utcnow().date() + timedelta(days=1 + i)
            start_dt = datetime.combine(start_day, time(hour=9))
            end_dt = datetime.combine(start_day, time(hour=17))
            event = Event(
                ngo_id=ngo.id,
                title=f"{ngo.organization_name} Event {i+1}",
                description=f"Help {ngo.organization_name} with a day of service.",
                location=f"{ngo.city} Center",
                start_date=start_dt,
                end_date=start_dt,
                max_volunteers=5,
                required_skills=json.dumps(["Coordination", "Teamwork"]),
                category=random.choice(categories),
                status='active',
                is_active=True,
                created_at=datetime.utcnow(),
            )
            db.session.add(event)
            db.session.flush()

            # 2-hour slots from 9 to 17
            for hour in range(9, 17, 2):
                st = datetime.combine(start_day, time(hour=hour))
                et = st + timedelta(hours=2)
                slot = TimeSlot(
                    event_id=event.id,
                    start_time=st,
                    end_time=et,
                    max_volunteers=event.max_volunteers,
                    current_volunteers=0,
                    is_available=True,
                )
                db.session.add(slot)

    db.session.flush()

    # Create a few bookings to populate leaderboards
    all_slots = TimeSlot.query.all()
    for vol in volunteers:
        for slot in random.sample(all_slots, min(2, len(all_slots))):
            if slot.current_volunteers < slot.max_volunteers and slot.is_available:
                booking = Booking(
                    volunteer_id=vol.id,
                    time_slot_id=slot.id,
                    event_id=slot.event_id,
                    status='completed',
                    hours_worked=2,
                    points_earned=20,
                    created_at=datetime.utcnow(),
                )
                slot.current_volunteers += 1
                if slot.current_volunteers >= slot.max_volunteers:
                    slot.is_available = False
                vol.total_hours += 2
                vol.total_points += 20
                db.session.add(booking)

    db.session.commit()


def main():
    from app import app  # use application context
    with app.app_context():
        db.create_all()
        create_sample_data()
        print("Database seeded with sample data.")


if __name__ == "__main__":
    main()


