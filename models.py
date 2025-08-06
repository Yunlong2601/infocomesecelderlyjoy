from datetime import datetime, timedelta
import secrets
import string
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from unified_security_system import encryption_manager

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
    
    # Reward system
    reward_points = db.Column(db.Integer, default=0)  # Points earned from participation
    
    # Email verification fields (for organizers/volunteers)
    email_verified = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    account_active = db.Column(db.Boolean, default=True)  # For admin user management
    
    # Relationships
    organized_events = db.relationship('Event', lazy=True, foreign_keys='Event.organizer_id')
    rsvps = db.relationship('EventRSVP', backref='user', lazy=True)
    volunteer_applications = db.relationship('VolunteerApplication', backref='volunteer', lazy=True)
    redeemed_rewards = db.relationship('UserReward', backref='user', lazy=True)

    # Override Flask-Login's is_active property to use our account_active field
    @property
    def is_active(self):
        """Override Flask-Login's is_active to use our account_active field"""
        return self.account_active

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
    
    def award_points(self, points, reason="Event participation"):
        """Award reward points to user"""
        if self.user_type in ['elderly', 'volunteer']:
            self.reward_points = (self.reward_points or 0) + points
            db.session.commit()
            return True
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
            from unified_security_system import encryption_manager
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
    
    # Admin review fields
    admin_remarks = db.Column(db.Text)  # Admin comments when approving/rejecting
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Admin who reviewed
    reviewed_at = db.Column(db.DateTime)  # When it was reviewed
    
    # Relationships
    rsvps = db.relationship('EventRSVP', backref='event', lazy=True)
    volunteer_applications = db.relationship('VolunteerApplication', backref='event', lazy=True)
    organizer = db.relationship('User', foreign_keys=[organizer_id])
    reviewer = db.relationship('User', foreign_keys=[reviewed_by])

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


class RewardVoucher(db.Model):
    """Model for available reward vouchers that users can redeem with points"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    points_required = db.Column(db.Integer, nullable=False)
    voucher_type = db.Column(db.String(50), nullable=False)  # 'discount', 'gift_card', 'service'
    voucher_value = db.Column(db.String(50), nullable=False)  # e.g., "$10 off", "Free coffee"
    partner_name = db.Column(db.String(100), nullable=True)  # Partner business name
    terms_conditions = db.Column(db.Text, nullable=True)
    expiry_days = db.Column(db.Integer, default=30)  # Voucher valid for X days after redemption
    is_active = db.Column(db.Boolean, default=True)
    stock_limit = db.Column(db.Integer, nullable=True)  # Optional stock limit
    redeemed_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user_rewards = db.relationship('UserReward', backref='voucher', lazy=True)
    
    @property
    def is_available(self):
        """Check if voucher is still available"""
        if not self.is_active:
            return False
        if self.stock_limit and self.redeemed_count >= self.stock_limit:
            return False
        return True


class UserReward(db.Model):
    """Model to track user reward redemptions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    voucher_id = db.Column(db.Integer, db.ForeignKey('reward_voucher.id'), nullable=False)
    points_spent = db.Column(db.Integer, nullable=False)
    redemption_code = db.Column(db.String(20), unique=True, nullable=False)
    redeemed_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime, nullable=True)
    
    @staticmethod
    def generate_redemption_code():
        """Generate a unique redemption code"""
        return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
    
    @classmethod
    def redeem_voucher(cls, user_id, voucher_id):
        """Redeem a voucher for a user"""
        from sqlalchemy import text
        
        # Get user and voucher
        user = User.query.get(user_id)
        voucher = RewardVoucher.query.get(voucher_id)
        
        if not user or not voucher:
            return None, "User or voucher not found"
        
        if not voucher.is_available:
            return None, "Voucher is no longer available"
        
        if user.reward_points < voucher.points_required:
            return None, f"Insufficient points. Need {voucher.points_required}, have {user.reward_points}"
        
        # Create redemption record
        redemption = cls(
            user_id=user_id,
            voucher_id=voucher_id,
            points_spent=voucher.points_required,
            redemption_code=cls.generate_redemption_code(),
            expires_at=datetime.utcnow() + timedelta(days=voucher.expiry_days)
        )
        
        # Deduct points and update voucher count
        user.reward_points -= voucher.points_required
        voucher.redeemed_count += 1
        
        db.session.add(redemption)
        db.session.commit()
        
        return redemption, "Voucher redeemed successfully"
    
    @property
    def is_expired(self):
        """Check if redemption has expired"""
        return datetime.utcnow() > self.expires_at and not self.is_used
