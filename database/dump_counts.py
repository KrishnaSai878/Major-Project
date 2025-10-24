#!/usr/bin/env python3
import os, sys
# Ensure project root on path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from database.models import db, User, NGO, Volunteer, Donor, Event, Project, Message, Resource, TimeSlot, Booking, AdminAuditLog


def main():
    with app.app_context():
        print(f"Users: {User.query.count()}")
        print(f"NGOs: {NGO.query.count()}")
        print(f"Volunteers: {Volunteer.query.count()}")
        print(f"Donors: {Donor.query.count()}")
        print(f"Events: {Event.query.count()}")
        print(f"Projects: {Project.query.count()}")
        print(f"Messages: {Message.query.count()}")
        print(f"Resources: {Resource.query.count()}")
        print(f"TimeSlots: {TimeSlot.query.count()}")
        print(f"Bookings: {Booking.query.count()}")
        print(f"AdminAuditLogs: {AdminAuditLog.query.count()}")


if __name__ == "__main__":
    main()
