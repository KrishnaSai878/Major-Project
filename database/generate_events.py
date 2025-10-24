#!/usr/bin/env python3
import os
import sys
import random
from datetime import datetime, timedelta

# Ensure project root on path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from database.models import db, NGO, Event


def random_future_datetime(days=45):
    base = datetime.utcnow()
    offset_days = random.randint(1, max(1, days))
    start_hour = random.choice([9, 10, 11, 13, 14, 15])
    # Start at chosen hour to look realistic
    dt = (base + timedelta(days=offset_days)).replace(hour=start_hour, minute=0, second=0, microsecond=0)
    return dt


def build_title(ngo_name: str, category: str) -> str:
    cat = (category or 'Community').split(',')[0].strip()
    seeds = [
        f"{cat} Drive with {ngo_name}",
        f"{cat} Outreach by {ngo_name}",
        f"{cat} Workshop - {ngo_name}",
        f"Community {cat} Event - {ngo_name}",
        f"{ngo_name} {cat} Program",
    ]
    return random.choice(seeds)[:100]


def event_exists(ngo_id: int, title: str, start_date: datetime) -> bool:
    # Idempotency check: same NGO + same title + same date (to the day)
    start_day = start_date.date()
    existing = (
        Event.query
        .filter(Event.ngo_id == ngo_id)
        .filter(Event.title == title)
        .filter(db.func.date(Event.start_date) == start_day)
        .first()
    )
    return existing is not None


def generate_events(per_ngo=2, limit_ngos=25, only_verified=True, window_days=45):
    created = 0
    q = NGO.query
    if only_verified:
        q = q.filter_by(is_verified=True)
    if limit_ngos:
        ngos = q.order_by(NGO.created_at.desc()).limit(limit_ngos).all()
    else:
        ngos = q.order_by(NGO.created_at.desc()).all()

    for ngo in ngos:
        for _ in range(per_ngo):
            start_dt = random_future_datetime(window_days)
            end_dt = start_dt + timedelta(hours=3)
            title = build_title(ngo.organization_name, ngo.category or '')
            if event_exists(ngo.id, title, start_dt):
                continue
            ev = Event(
                ngo_id=ngo.id,
                title=title,
                description=f"Auto-generated event for {ngo.organization_name}",
                location=ngo.city or (ngo.state or 'Online'),
                start_date=start_dt,
                end_date=end_dt,
                max_volunteers=random.choice([10, 15, 20, 25, 30]),
                required_skills=None,
                category=(ngo.category or 'General')[:50],
                image=None,
                status='active',
                is_active=True,
            )
            db.session.add(ev)
            created += 1
        # Commit per NGO to avoid losing progress
        db.session.commit()
    return created, len(ngos)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate sample events for NGOs')
    parser.add_argument('--per-ngo', type=int, default=2)
    parser.add_argument('--limit-ngos', type=int, default=25, help='Set 0 to process all NGOs')
    parser.add_argument('--only-verified', action='store_true', default=True, help='Process only verified NGOs (default)')
    parser.add_argument('--include-unverified', action='store_true', default=False, help='Include unverified NGOs as well')
    parser.add_argument('--window-days', type=int, default=45)
    args = parser.parse_args()

    with app.app_context():
        only_verified = args.only_verified and not args.include_unverified
        limit_ngos = args.limit_ngos if args.limit_ngos != 0 else None
        created, total_ngos = generate_events(
            per_ngo=args.per_ngo,
            limit_ngos=limit_ngos,
            only_verified=only_verified,
            window_days=args.window_days,
        )
        print(f"NGOs processed: {total_ngos}")
        print(f"Events created: {created}")


if __name__ == '__main__':
    main()
