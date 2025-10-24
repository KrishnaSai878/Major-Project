#!/usr/bin/env python3
import os
import sys
from datetime import datetime, timedelta

# Ensure project root on path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from database.models import db, Event, TimeSlot


def create_timeslots_for_event(event: Event) -> int:
    # If event already has any slots, skip to keep idempotent
    existing = TimeSlot.query.filter_by(event_id=event.id).count()
    if existing > 0:
        return 0

    start_date = event.start_date
    end_date = event.end_date
    current_date = start_date
    created = 0

    while current_date <= end_date:
        # Create 2-hour slots from 9 AM to 5 PM (last slot 15-17)
        for hour in range(9, 17, 2):
            start_time = datetime.combine(current_date, datetime.min.time().replace(hour=hour))
            end_time = start_time + timedelta(hours=2)
            slot = TimeSlot(
                event_id=event.id,
                start_time=start_time,
                end_time=end_time,
                max_volunteers=event.max_volunteers or 10,
                current_volunteers=0,
                is_available=True,
            )
            db.session.add(slot)
            created += 1
        current_date += timedelta(days=1)

    return created


def main():
    with app.app_context():
        total_events = 0
        total_created = 0
        for event in Event.query.order_by(Event.start_date.asc()).all():
            total_events += 1
            made = create_timeslots_for_event(event)
            if made:
                db.session.commit()
                total_created += made
        print(f"Events scanned: {total_events}")
        print(f"Time slots created: {total_created}")


if __name__ == "__main__":
    main()
