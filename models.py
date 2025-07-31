from datetime import datetime, timedelta
import secrets
import string
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from encryption_manager import encryption_manager

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
    is_active = db.Column(db.Boolean, default=True)  # For admin user management
    
    # Relationships
    organized_events = db.relationship('Event', backref='organizer', lazy=True, foreign_keys='Event.organizer_id')
    rsvps = db.relationship('EventRSVP', backref='user', lazy=True)
    volunteer_applications = db.relationship('VolunteerApplication', backref='volunteer', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def encrypt_sensitive_data(self):
        """Encrypt sensitive user data using AES-256"""
        if self.nric and not self.is_encrypted(self.nric):
            self.nric = encryption_manager.encrypt_data(self.nric)
        if self.phone and not self.is_encrypted(self.phone):
            self.phone = encryption_manager.encrypt_data(self.phone)
    
    def is_encrypted(self, data):
        """Check if data is already encrypted"""
        try:
            # Try to decode as base64 - encrypted data will be base64 encoded
            import base64
            base64.b64decode(data)
            return len(data) > 20  # Encrypted data is longer
        except:
            return False
    
    def set_security_answers(self, answer1, answer2, answer3):
        """Hash and store security answers securely"""
        if answer1:
            self.security_a1 = generate_password_hash(answer1.lower().strip())
        if answer2:
            self.security_a2 = generate_password_hash(answer2.lower().strip())
        if answer3:
            self.security_a3 = generate_password_hash(answer3.lower().strip())
    
    def check_security_answer(self, answer_number, provided_answer):
        """Check security answer against stored hash"""
        if not provided_answer:
            return False
        
        normalized_answer = provided_answer.lower().strip()
        
        if answer_number == 1 and self.security_a1:
            return check_password_hash(self.security_a1, normalized_answer)
        elif answer_number == 2 and self.security_a2:
            return check_password_hash(self.security_a2, normalized_answer)
        elif answer_number == 3 and self.security_a3:
            return check_password_hash(self.security_a3, normalized_answer)
        
        return False
    
    def decrypt_sensitive_data(self):
        """Decrypt sensitive user data (NRIC and phone only - answers are hashed)"""
        decrypted_data = {}
        try:
            if self.nric:
                decrypted_data['nric'] = encryption_manager.decrypt_data(self.nric)
            if self.phone:
                decrypted_data['phone'] = encryption_manager.decrypt_data(self.phone)
        except Exception:
            # Data might not be encrypted yet
            decrypted_data = {
                'nric': self.nric,
                'phone': self.phone
            }
        
        # Security answers are hashed, not encrypted - never return them
        decrypted_data.update({
            'security_a1': '[HASHED]',
            'security_a2': '[HASHED]', 
            'security_a3': '[HASHED]'
        })
        
        return decrypted_data
    
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
            from encryption_manager import encryption_manager
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
