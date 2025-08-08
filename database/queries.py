#!/usr/bin/env python3
"""
Database Queries Module
Common database operations and optimized queries
"""

from sqlalchemy import and_, or_, func, desc, asc
from datetime import datetime, timedelta
import json

class DatabaseQueries:
    def __init__(self, db, models):
        self.db = db
        self.models = models
    
    # User Queries
    def get_user_by_email(self, email):
        """Get user by email"""
        return self.models.User.query.filter_by(email=email).first()
    
    def get_users_by_role(self, role, limit=None):
        """Get users by role"""
        query = self.models.User.query.filter_by(role=role, is_active=True)
        if limit:
            query = query.limit(limit)
        return query.all()
    
    def get_verified_ngos(self, limit=None):
        """Get verified NGOs"""
        query = self.models.NGO.query.filter_by(is_verified=True)
        if limit:
            query = query.limit(limit)
        return query.all()
    
    def search_ngos(self, search_term, category=None, city=None):
        """Search NGOs with filters"""
        query = self.models.NGO.query.filter(self.models.NGO.is_verified == True)
        
        if search_term:
            query = query.filter(
                or_(
                    self.models.NGO.organization_name.ilike(f'%{search_term}%'),
                    self.models.NGO.description.ilike(f'%{search_term}%'),
                    self.models.NGO.mission.ilike(f'%{search_term}%')
                )
            )
        
        if category:
            query = query.filter(self.models.NGO.category == category)
        
        if city:
            query = query.filter(self.models.NGO.city.ilike(f'%{city}%'))
        
        return query.all()
    
    # Event Queries
    def get_active_events(self, limit=None):
        """Get active events"""
        query = self.models.Event.query.filter_by(status='active')
        if limit:
            query = query.limit(limit)
        return query.all()
    
    def get_events_by_category(self, category, limit=None):
        """Get events by category"""
        query = self.models.Event.query.filter_by(category=category, status='active')
        if limit:
            query = query.limit(limit)
        return query.all()
    
    def get_upcoming_events(self, days=30, limit=None):
        """Get upcoming events within specified days"""
        future_date = datetime.now() + timedelta(days=days)
        query = self.models.Event.query.filter(
            and_(
                self.models.Event.status == 'active',
                self.models.Event.start_date >= datetime.now(),
                self.models.Event.start_date <= future_date
            )
        ).order_by(asc(self.models.Event.start_date))
        
        if limit:
            query = query.limit(limit)
        return query.all()
    
    def search_events(self, search_term, category=None, location=None):
        """Search events with filters"""
        query = self.models.Event.query.filter_by(status='active')
        
        if search_term:
            query = query.filter(
                or_(
                    self.models.Event.title.ilike(f'%{search_term}%'),
                    self.models.Event.description.ilike(f'%{search_term}%')
                )
            )
        
        if category:
            query = query.filter(self.models.Event.category == category)
        
        if location:
            query = query.filter(self.models.Event.location.ilike(f'%{location}%'))
        
        return query.order_by(asc(self.models.Event.start_date)).all()
    
    # Time Slot Queries
    def get_available_time_slots(self, event_id):
        """Get available time slots for an event"""
        return self.models.TimeSlot.query.filter(
            and_(
                self.models.TimeSlot.event_id == event_id,
                self.models.TimeSlot.is_available == True
            )
        ).order_by(asc(self.models.TimeSlot.start_time)).all()
    
    def get_time_slots_by_date(self, event_id, date):
        """Get time slots for a specific date"""
        start_of_day = datetime.combine(date, datetime.min.time())
        end_of_day = datetime.combine(date, datetime.max.time())
        
        return self.models.TimeSlot.query.filter(
            and_(
                self.models.TimeSlot.event_id == event_id,
                self.models.TimeSlot.start_time >= start_of_day,
                self.models.TimeSlot.start_time <= end_of_day
            )
        ).order_by(asc(self.models.TimeSlot.start_time)).all()
    
    # Booking Queries
    def get_user_bookings(self, user_id, status=None):
        """Get bookings for a user"""
        query = self.models.Booking.query.join(self.models.Volunteer).filter(
            self.models.Volunteer.user_id == user_id
        )
        
        if status:
            query = query.filter(self.models.Booking.status == status)
        
        return query.order_by(desc(self.models.Booking.created_at)).all()
    
    def get_event_bookings(self, event_id, status=None):
        """Get bookings for an event"""
        query = self.models.Booking.query.filter_by(event_id=event_id)
        
        if status:
            query = query.filter(self.models.Booking.status == status)
        
        return query.all()
    
    def get_volunteer_stats(self, volunteer_id):
        """Get volunteer statistics"""
        bookings = self.models.Booking.query.filter_by(volunteer_id=volunteer_id)
        
        total_bookings = bookings.count()
        completed_bookings = bookings.filter_by(status='completed').count()
        total_hours = bookings.with_entities(
            func.sum(self.models.Booking.hours_worked)
        ).scalar() or 0
        total_points = bookings.with_entities(
            func.sum(self.models.Booking.points_earned)
        ).scalar() or 0
        
        return {
            'total_bookings': total_bookings,
            'completed_bookings': completed_bookings,
            'total_hours': total_hours,
            'total_points': total_points
        }
    
    # Message Queries
    def get_user_messages(self, user_id, limit=None):
        """Get messages for a user (both sent and received)"""
        query = self.models.Message.query.filter(
            or_(
                self.models.Message.sender_id == user_id,
                self.models.Message.receiver_id == user_id
            )
        ).order_by(desc(self.models.Message.created_at))
        
        if limit:
            query = query.limit(limit)
        
        return query.all()
    
    def get_conversation(self, user1_id, user2_id, limit=None):
        """Get conversation between two users"""
        query = self.models.Message.query.filter(
            or_(
                and_(
                    self.models.Message.sender_id == user1_id,
                    self.models.Message.receiver_id == user2_id
                ),
                and_(
                    self.models.Message.sender_id == user2_id,
                    self.models.Message.receiver_id == user1_id
                )
            )
        ).order_by(asc(self.models.Message.created_at))
        
        if limit:
            query = query.limit(limit)
        
        return query.all()
    
    def get_unread_messages_count(self, user_id):
        """Get count of unread messages for a user"""
        return self.models.Message.query.filter(
            and_(
                self.models.Message.receiver_id == user_id,
                self.models.Message.is_read == False
            )
        ).count()
    
    # Analytics Queries
    def get_platform_stats(self):
        """Get platform statistics for admin dashboard"""
        stats = {}
        
        # User counts
        stats['total_users'] = self.models.User.query.count()
        stats['total_ngos'] = self.models.NGO.query.count()
        stats['total_volunteers'] = self.models.Volunteer.query.count()
        stats['total_donors'] = self.models.Donor.query.count()
        
        # Event counts
        stats['total_events'] = self.models.Event.query.count()
        stats['active_events'] = self.models.Event.query.filter_by(status='active').count()
        
        # Booking counts
        stats['total_bookings'] = self.models.Booking.query.count()
        stats['completed_bookings'] = self.models.Booking.query.filter_by(status='completed').count()
        
        # Recent activity (last 30 days)
        thirty_days_ago = datetime.now() - timedelta(days=30)
        stats['recent_users'] = self.models.User.query.filter(
            self.models.User.created_at >= thirty_days_ago
        ).count()
        
        stats['recent_events'] = self.models.Event.query.filter(
            self.models.Event.created_at >= thirty_days_ago
        ).count()
        
        return stats
    
    def get_ngo_stats(self, ngo_id):
        """Get statistics for a specific NGO"""
        stats = {}
        
        # Event counts
        stats['total_events'] = self.models.Event.query.filter_by(ngo_id=ngo_id).count()
        stats['active_events'] = self.models.Event.query.filter_by(
            ngo_id=ngo_id, status='active'
        ).count()
        
        # Volunteer counts
        event_ids = [e.id for e in self.models.Event.query.filter_by(ngo_id=ngo_id).all()]
        if event_ids:
            stats['total_volunteers'] = self.models.Booking.query.filter(
                self.models.Booking.event_id.in_(event_ids)
            ).distinct(self.models.Booking.volunteer_id).count()
        else:
            stats['total_volunteers'] = 0
        
        # Hours contributed
        if event_ids:
            stats['total_hours'] = self.models.Booking.query.filter(
                self.models.Booking.event_id.in_(event_ids)
            ).with_entities(
                func.sum(self.models.Booking.hours_worked)
            ).scalar() or 0
        else:
            stats['total_hours'] = 0
        
        return stats
    
    def get_volunteer_leaderboard(self, limit=10):
        """Get volunteer leaderboard by points"""
        return self.models.Volunteer.query.order_by(
            desc(self.models.Volunteer.total_points)
        ).limit(limit).all()
    
    def get_hours_leaderboard(self, limit=10):
        """Get volunteer leaderboard by hours"""
        return self.models.Volunteer.query.order_by(
            desc(self.models.Volunteer.total_hours)
        ).limit(limit).all()
    
    def get_ngo_leaderboard_by_volunteers(self, limit=10):
        """Top NGOs by distinct volunteers booked across their events"""
        NGO = self.models.NGO
        Event = self.models.Event
        Booking = self.models.Booking
        q = (
            self.db.session.query(
                NGO,
                func.count(func.distinct(Booking.volunteer_id)).label('volunteer_count')
            )
            .join(Event, Event.ngo_id == NGO.id)
            .join(Booking, Booking.event_id == Event.id)
            .group_by(NGO.id)
            .order_by(desc('volunteer_count'))
            .limit(limit)
        )
        return q.all()

    def get_ngo_leaderboard_by_hours(self, limit=10):
        """Top NGOs by total hours worked across their events"""
        NGO = self.models.NGO
        Event = self.models.Event
        Booking = self.models.Booking
        q = (
            self.db.session.query(
                NGO,
                func.coalesce(func.sum(Booking.hours_worked), 0).label('total_hours')
            )
            .join(Event, Event.ngo_id == NGO.id)
            .join(Booking, Booking.event_id == Event.id)
            .group_by(NGO.id)
            .order_by(desc('total_hours'))
            .limit(limit)
        )
        return q.all()
    
    # Search and Recommendation Queries
    def get_recommended_events(self, volunteer_id, limit=5):
        """Get recommended events for a volunteer based on skills and interests"""
        volunteer = self.models.Volunteer.query.filter_by(id=volunteer_id).first()
        if not volunteer:
            return []
        
        volunteer_skills = volunteer.get_skills_list()
        volunteer_interests = volunteer.get_interests_list()
        
        # Find events that match volunteer's skills or interests
        matching_events = []
        
        for event in self.models.Event.query.filter_by(status='active').all():
            event_skills = event.get_required_skills()
            
            # Check for skill matches
            skill_matches = len(set(volunteer_skills) & set(event_skills))
            
            # Check for interest matches
            interest_matches = 0
            if event.category in volunteer_interests:
                interest_matches = 1
            
            # Calculate match score
            match_score = skill_matches + interest_matches
            
            if match_score > 0:
                matching_events.append((event, match_score))
        
        # Sort by match score and return top results
        matching_events.sort(key=lambda x: x[1], reverse=True)
        return [event for event, score in matching_events[:limit]]
    
    def get_recommended_ngos(self, donor_id, limit=5):
        """Get recommended NGOs for a donor based on preferences"""
        donor = self.models.Donor.query.filter_by(id=donor_id).first()
        if not donor:
            return []
        
        preferences = donor.get_preferences()
        preferred_categories = preferences.get('categories', [])
        
        if not preferred_categories:
            return self.models.NGO.query.filter_by(is_verified=True).limit(limit).all()
        
        return self.models.NGO.query.filter(
            and_(
                self.models.NGO.is_verified == True,
                self.models.NGO.category.in_(preferred_categories)
            )
        ).limit(limit).all()

# Create a global instance
queries = None

def init_queries(db, models):
    """Initialize the global queries instance.
    Accepts either a module-like object with attributes or a dict of models.
    """
    from types import SimpleNamespace

    global queries
    if isinstance(models, dict):
        models = SimpleNamespace(**models)
    queries = DatabaseQueries(db, models)
    return queries
