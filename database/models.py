from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, index=True)  # admin, ngo, volunteer, donor
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    profile_image = db.Column(db.String(200))
    is_verified = db.Column(db.Boolean, default=False, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    ngo = db.relationship('NGO', backref='user', uselist=False, cascade='all, delete-orphan')
    volunteer = db.relationship('Volunteer', backref='user', uselist=False, cascade='all, delete-orphan')
    donor = db.relationship('Donor', backref='user', uselist=False, cascade='all, delete-orphan')
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')

class NGO(db.Model):
    __tablename__ = 'ngos'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    organization_name = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text)
    mission = db.Column(db.Text)
    website = db.Column(db.String(200))
    address = db.Column(db.Text)
    city = db.Column(db.String(50), index=True)
    state = db.Column(db.String(50), index=True)
    zip_code = db.Column(db.String(10))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    logo = db.Column(db.String(200))
    category = db.Column(db.String(50), index=True)
    established_year = db.Column(db.Integer)
    is_verified = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    events = db.relationship('Event', backref='ngo', lazy='dynamic', cascade='all, delete-orphan')
    resources = db.relationship('Resource', backref='ngo', lazy='dynamic', cascade='all, delete-orphan')
    projects = db.relationship('Project', backref='ngo', lazy='dynamic', cascade='all, delete-orphan')

class Volunteer(db.Model):
    __tablename__ = 'volunteers'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    bio = db.Column(db.Text)
    skills = db.Column(db.Text)  # JSON string of skills
    interests = db.Column(db.Text)  # JSON string of interests
    availability = db.Column(db.Text)  # JSON string of availability
    total_hours = db.Column(db.Integer, default=0, index=True)
    total_points = db.Column(db.Integer, default=0, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    bookings = db.relationship('Booking', backref='volunteer', lazy='dynamic', cascade='all, delete-orphan')
    
    def get_skills_list(self):
        """Get skills as a list"""
        if self.skills:
            return json.loads(self.skills)
        return []
    
    def get_interests_list(self):
        """Get interests as a list"""
        if self.interests:
            return json.loads(self.interests)
        return []
    
    def get_availability_dict(self):
        """Get availability as a dictionary"""
        if self.availability:
            return json.loads(self.availability)
        return {}

class Donor(db.Model):
    __tablename__ = 'donors'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    company_name = db.Column(db.String(100))
    donation_history = db.Column(db.Text)  # JSON string
    preferences = db.Column(db.Text)  # JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def get_donation_history(self):
        """Get donation history as a list"""
        if self.donation_history:
            return json.loads(self.donation_history)
        return []
    
    def get_preferences(self):
        """Get preferences as a dictionary"""
        if self.preferences:
            return json.loads(self.preferences)
        return {}

class Event(db.Model):
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    ngo_id = db.Column(db.Integer, db.ForeignKey('ngos.id'), nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text)
    location = db.Column(db.String(200))
    start_date = db.Column(db.DateTime, nullable=False, index=True)
    end_date = db.Column(db.DateTime, nullable=False, index=True)
    max_volunteers = db.Column(db.Integer)
    required_skills = db.Column(db.Text)  # JSON string
    category = db.Column(db.String(50), index=True)
    image = db.Column(db.String(200))
    status = db.Column(db.String(20), default='active', index=True)  # active, completed, cancelled
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    time_slots = db.relationship('TimeSlot', backref='event', lazy='dynamic', cascade='all, delete-orphan')
    bookings = db.relationship('Booking', backref='event', lazy='dynamic', cascade='all, delete-orphan')
    
    def get_required_skills(self):
        """Get required skills as a list"""
        if self.required_skills:
            return json.loads(self.required_skills)
        return []

class TimeSlot(db.Model):
    __tablename__ = 'time_slots'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False, index=True)
    start_time = db.Column(db.DateTime, nullable=False, index=True)
    end_time = db.Column(db.DateTime, nullable=False, index=True)
    max_volunteers = db.Column(db.Integer, default=1)
    current_volunteers = db.Column(db.Integer, default=0)
    is_available = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    bookings = db.relationship('Booking', backref='time_slot', lazy='dynamic', cascade='all, delete-orphan')

class Booking(db.Model):
    __tablename__ = 'bookings'
    
    id = db.Column(db.Integer, primary_key=True)
    volunteer_id = db.Column(db.Integer, db.ForeignKey('volunteers.id'), nullable=False, index=True)
    time_slot_id = db.Column(db.Integer, db.ForeignKey('time_slots.id'), nullable=False, index=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False, index=True)
    status = db.Column(db.String(20), default='confirmed', index=True)  # confirmed, completed, cancelled
    hours_worked = db.Column(db.Float, default=0)
    points_earned = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Resource(db.Model):
    __tablename__ = 'resources'
    
    id = db.Column(db.Integer, primary_key=True)
    ngo_id = db.Column(db.Integer, db.ForeignKey('ngos.id'), nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(200))
    file_type = db.Column(db.String(50))
    is_public = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Project(db.Model):
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    ngo_id = db.Column(db.Integer, db.ForeignKey('ngos.id'), nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='active', index=True)  # active, completed, on-hold
    start_date = db.Column(db.DateTime, index=True)
    end_date = db.Column(db.DateTime, index=True)
    progress = db.Column(db.Integer, default=0)  # percentage
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
