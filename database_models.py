"""
Database Models for Community Connect

This file contains all SQL database table definitions and relationships
for the Community Connect application, separated for easier code review.
"""

from datetime import datetime, timedelta
import secrets
import string
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from comprehensive_security_system import encryption_manager

class User(UserMixin, db.Model):
    """User model supporting elderly, organizer, volunteer, and admin roles"""
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
    
    # Reward system
    reward_points = db.Column(db.Integer, default=0)  # Points earned from participation
    
    # Email verification fields (for organizers/volunteers)
    email_verified = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)  # For admin user management
    
    # Relationships
    organized_events = db.relationship('Event', foreign_keys='Event.organizer_id', backref='organizer', lazy='dynamic')
    event_rsvps = db.relationship('EventRSVP', foreign_keys='EventRSVP.user_id', backref='user', lazy='dynamic')
    volunteer_applications = db.relationship('VolunteerApplication', foreign_keys='VolunteerApplication.volunteer_id', backref='volunteer', lazy='dynamic')
    email_verifications = db.relationship('EmailVerification', foreign_keys='EmailVerification.user_id', backref='user', lazy='dynamic')
    user_rewards = db.relationship('UserReward', foreign_keys='UserReward.user_id', backref='user', lazy='dynamic')

    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def generate_verification_token(self):
        """Generate verification token for email verification"""
        return secrets.token_urlsafe(32)
    
    def verify_security_answer(self, question_num, answer):
        """Verify security answer"""
        from werkzeug.security import check_password_hash
        
        answer_hash = getattr(self, f'security_a{question_num}')
        if answer_hash:
            return check_password_hash(answer_hash, answer.lower().strip())
        return False
    
    def get_display_name(self):
        """Get user's display name based on user type"""
        if self.user_type == 'elderly':
            return self.full_name or "Community Member"
        elif self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.username:
            return self.username
        else:
            return "User"
    
    @classmethod
    def safe_query_by_nric(cls, nric_value):
        """Safely query user by NRIC - temporarily using direct match for debugging"""
        import re
        
        # Check if it looks like an NRIC format
        if not re.match(r'^[STFG]\d{7}[A-Z]$', nric_value):
            return None
            
        # First try direct match (for unencrypted data)
        user = cls.query.filter(cls.nric == nric_value).first()
        if user:
            return user
            
        # If no direct match found, try decrypting encrypted values
        try:
            elderly_users = cls.query.filter_by(user_type='elderly').all()
            for user in elderly_users:
                if user.nric and len(user.nric) > 20:  # Likely encrypted
                    try:
                        decrypted_nric = encryption_manager.decrypt_data(user.nric)
                        if decrypted_nric == nric_value:
                            return user
                    except Exception:
                        continue
        except Exception:
            pass
            
        return None
    
    @classmethod
    def safe_query_by_email(cls, email_value):
        """Safely query user by email using ORM parameterized queries"""
        return cls.query.filter(cls.email == email_value).first()

    def get_full_name(self):
        if self.user_type == 'elderly':
            return self.full_name or 'Elderly User'
        return f"{self.first_name} {self.last_name}" if self.first_name and self.last_name else 'User'

class Event(db.Model):
    """Event model for community activities"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), nullable=False)  # social, recreational, educational
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    max_participants = db.Column(db.Integer, default=50)
    volunteers_needed = db.Column(db.Integer, default=0)
    organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Duration and admin review fields
    duration_hours = db.Column(db.Integer, nullable=True)
    admin_remarks = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    rsvps = db.relationship('EventRSVP', foreign_keys='EventRSVP.event_id', backref='event', lazy='dynamic', cascade='all, delete-orphan')
    volunteer_applications = db.relationship('VolunteerApplication', foreign_keys='VolunteerApplication.event_id', backref='event', lazy='dynamic', cascade='all, delete-orphan')
    reviewer = db.relationship('User', foreign_keys=[reviewed_by])

    def get_rsvp_count(self):
        """Get count of confirmed RSVPs"""
        return self.rsvps.filter_by(status='confirmed').count()
    
    def get_available_spots(self):
        """Get number of available spots"""
        return max(0, self.max_participants - self.get_rsvp_count())
    
    def is_full(self):
        """Check if event is at capacity"""
        return self.get_rsvp_count() >= self.max_participants
    
    def get_volunteer_count(self):
        """Get count of approved volunteers"""
        return self.volunteer_applications.filter_by(status='approved').count()
    
    def needs_volunteers(self):
        """Check if event still needs volunteers"""
        return self.get_volunteer_count() < self.volunteers_needed

class EventRSVP(db.Model):
    """RSVP model for event participation"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    status = db.Column(db.String(20), default='confirmed')  # confirmed, cancelled
    rsvp_date = db.Column(db.DateTime, default=datetime.utcnow)
    attendance_confirmed = db.Column(db.Boolean, default=False)  # For reward points
    
    # Unique constraint to prevent duplicate RSVPs
    __table_args__ = (db.UniqueConstraint('user_id', 'event_id', name='unique_user_event_rsvp'),)

class VolunteerApplication(db.Model):
    """Volunteer application model"""
    id = db.Column(db.Integer, primary_key=True)
    volunteer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    message = db.Column(db.Text)  # Why they want to volunteer
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Unique constraint to prevent duplicate applications
    __table_args__ = (db.UniqueConstraint('volunteer_id', 'event_id', name='unique_volunteer_event_application'),)

class EmailVerification(db.Model):
    """Email verification model for 2FA"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    verification_code = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    def __init__(self, user_id, email, verification_code):
        self.user_id = user_id
        self.email = email
        self.verification_code = verification_code
        self.expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    def is_expired(self):
        """Check if verification code has expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self, code):
        """Check if provided code is valid and not expired"""
        return (not self.is_used and 
                not self.is_expired() and 
                self.verification_code == code)

class RewardVoucher(db.Model):
    """Reward voucher model for point redemption"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    points_required = db.Column(db.Integer, nullable=False)
    voucher_code = db.Column(db.String(50))  # Optional voucher code
    terms_conditions = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user_rewards = db.relationship('UserReward', foreign_keys='UserReward.voucher_id', backref='voucher', lazy='dynamic')

class UserReward(db.Model):
    """User reward redemption model"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    voucher_id = db.Column(db.Integer, db.ForeignKey('reward_voucher.id'), nullable=False)
    points_spent = db.Column(db.Integer, nullable=False)
    redeemed_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_used = db.Column(db.Boolean, default=False)
    unique_code = db.Column(db.String(20), unique=True, nullable=False)  # Unique redemption code
    
    def __init__(self, user_id, voucher_id, points_spent):
        self.user_id = user_id
        self.voucher_id = voucher_id
        self.points_spent = points_spent
        self.unique_code = self.generate_unique_code()
    
    def generate_unique_code(self):
        """Generate unique redemption code"""
        letters = string.ascii_uppercase
        numbers = string.digits
        return ''.join(secrets.choice(letters + numbers) for _ in range(8))