from datetime import datetime, timedelta
import secrets
import string
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # For elderly users - NRIC as unique identifier
    nric = db.Column(db.String(9), unique=True, nullable=True)  # For elderly users
    full_name = db.Column(db.String(100), nullable=True)  # For elderly users
    language_preference = db.Column(db.String(20), nullable=True)  # For elderly users
    event_interests = db.Column(db.Text, nullable=True)  # JSON string of interests for elderly
    
    # Security questions for 2FA (elderly users)
    security_q1 = db.Column(db.String(100), nullable=True)
    security_a1 = db.Column(db.String(200), nullable=True)
    security_q2 = db.Column(db.String(100), nullable=True)
    security_a2 = db.Column(db.String(200), nullable=True)
    security_q3 = db.Column(db.String(100), nullable=True)
    security_a3 = db.Column(db.String(200), nullable=True)
    
    # For organizers/volunteers - traditional fields
    username = db.Column(db.String(64), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    phone = db.Column(db.String(20))
    
    # Common fields
    password_hash = db.Column(db.String(256), nullable=False)
    user_type = db.Column(db.String(20), nullable=False, default='elderly')  # elderly, organizer, volunteer, admin
    profile_picture = db.Column(db.String(255), nullable=True)  # Path to profile picture
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Email verification fields (for organizers/volunteers)
    email_verified = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    
    # Relationships
    organized_events = db.relationship('Event', backref='organizer', lazy=True, foreign_keys='Event.organizer_id')
    rsvps = db.relationship('EventRSVP', backref='user', lazy=True)
    volunteer_applications = db.relationship('VolunteerApplication', backref='volunteer', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_full_name(self):
        if self.user_type == 'elderly':
            return self.full_name or 'Elderly User'
        return f"{self.first_name} {self.last_name}" if self.first_name and self.last_name else 'User'
    
    def get_display_name(self):
        if self.user_type == 'elderly':
            return self.nric or 'Unknown NRIC'
        return self.username or self.email or 'Unknown User'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), nullable=False)  # social, recreational, educational
    date = db.Column(db.DateTime, nullable=False)
    duration_hours = db.Column(db.Integer, default=2)
    location = db.Column(db.String(200), nullable=False)
    max_participants = db.Column(db.Integer)
    volunteers_needed = db.Column(db.Integer, default=0)
    organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    rsvps = db.relationship('EventRSVP', backref='event', lazy=True)
    volunteer_applications = db.relationship('VolunteerApplication', backref='event', lazy=True)

    def get_rsvp_count(self):
        return EventRSVP.query.filter_by(event_id=self.id).count()

    def get_volunteer_count(self):
        return VolunteerApplication.query.filter_by(event_id=self.id, status='approved').count()

    def is_full(self):
        if self.max_participants:
            return self.get_rsvp_count() >= self.max_participants
        return False

class EventRSVP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure one RSVP per user per event
    __table_args__ = (db.UniqueConstraint('user_id', 'event_id', name='unique_user_event_rsvp'),)

class VolunteerApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    volunteer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure one application per volunteer per event
    __table_args__ = (db.UniqueConstraint('volunteer_id', 'event_id', name='unique_volunteer_event_application'),)

class EmailVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    verification_code = db.Column(db.String(6), nullable=False)
    purpose = db.Column(db.String(20), nullable=False)  # 'login', 'password_reset', 'email_change'
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)
    
    # Relationship
    user = db.relationship('User', backref='email_verifications')
    
    @staticmethod
    def generate_code():
        """Generate a 6-digit verification code"""
        return ''.join(secrets.choice(string.digits) for _ in range(6))
    
    @classmethod
    def create_verification(cls, user_id, email, purpose, expiry_minutes=10):
        """Create a new email verification record"""
        # Clean up old verification codes for this user and purpose
        cls.query.filter_by(user_id=user_id, purpose=purpose, used=False).delete()
        db.session.commit()
        
        verification = cls(
            user_id=user_id,
            email=email,
            verification_code=cls.generate_code(),
            purpose=purpose,
            expires_at=datetime.utcnow() + timedelta(minutes=expiry_minutes)
        )
        db.session.add(verification)
        db.session.commit()
        return verification
    
    def is_valid(self):
        """Check if the verification code is still valid"""
        return not self.used and datetime.utcnow() < self.expires_at
    
    def mark_used(self):
        """Mark the verification code as used"""
        self.used = True
        db.session.commit()
