from datetime import datetime
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    user_type = db.Column(db.String(20), nullable=False, default='elderly')  # elderly, organizer, volunteer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    organized_events = db.relationship('Event', backref='organizer', lazy=True, foreign_keys='Event.organizer_id')
    rsvps = db.relationship('EventRSVP', backref='user', lazy=True)
    volunteer_applications = db.relationship('VolunteerApplication', backref='volunteer', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

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
