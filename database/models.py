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


class Donation(db.Model):
    __tablename__ = 'donations'
    __table_args__ = (
        db.UniqueConstraint('network', 'tx_hash', name='uq_donations_network_tx'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donors.id'), nullable=True, index=True)
    ngo_id = db.Column(db.Integer, db.ForeignKey('ngos.id'), nullable=False, index=True)
    amount_inr = db.Column(db.Float, nullable=True)
    amount_crypto = db.Column(db.Float, nullable=True)
    currency = db.Column(db.String(20), nullable=True)  # e.g., MATIC, ETH, USDT
    network = db.Column(db.String(50), nullable=True)   # e.g., polygon-amoy, sepolia
    tx_hash = db.Column(db.String(100), index=True)
    message = db.Column(db.Text)
    anonymous = db.Column(db.Boolean, default=False, index=True)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, confirmed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    donor = db.relationship('Donor', backref='donations', foreign_keys=[donor_id])
    ngo = db.relationship('NGO', backref='donations', foreign_keys=[ngo_id])

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
    # Attendance fields
    check_in_at = db.Column(db.DateTime, index=True)
    check_out_at = db.Column(db.DateTime, index=True)
    attendance_status = db.Column(db.String(20), default='pending', index=True)  # pending, present, absent


class AttendanceToken(db.Model):
    __tablename__ = 'attendance_tokens'
    id = db.Column(db.Integer, primary_key=True)
    ngo_id = db.Column(db.Integer, db.ForeignKey('ngos.id'), nullable=False, index=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False, index=True)
    time_slot_id = db.Column(db.Integer, db.ForeignKey('time_slots.id'), nullable=True, index=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)

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

class AdminAuditLog(db.Model):
    __tablename__ = 'admin_audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=False, index=True)  # user, ngo, event, etc.
    resource_id = db.Column(db.Integer, index=True)
    action_details = db.Column(db.Text)  # JSON string with additional details
    ip_address = db.Column(db.String(45), index=True)
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success = db.Column(db.Boolean, default=True, index=True)
    error_message = db.Column(db.Text)
    
    # Relationships
    admin_user = db.relationship('User', backref='audit_logs', foreign_keys=[admin_user_id])

class AdminRole(db.Model):
    __tablename__ = 'admin_roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    description = db.Column(db.Text)
    permissions = db.Column(db.Text)  # JSON string of permissions
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def get_permissions(self):
        """Get permissions as a dictionary"""
        if self.permissions:
            return json.loads(self.permissions)
        return {}
    
    def has_permission(self, permission):
        """Check if role has specific permission"""
        permissions = self.get_permissions()
        return permissions.get(permission, False)

class AdminUserRole(db.Model):
    __tablename__ = 'admin_user_roles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('admin_roles.id'), nullable=False, index=True)
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, index=True)  # Optional expiration
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    # Relationships
    user = db.relationship('User', backref='admin_roles', foreign_keys=[user_id])
    role = db.relationship('AdminRole', backref='user_assignments', foreign_keys=[role_id])
    assigned_by_user = db.relationship('User', foreign_keys=[assigned_by])
    progress = db.Column(db.Integer, default=0)  # percentage
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
