from datetime import datetime
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from models import User, Event, EventRSVP, VolunteerApplication
from forms import LoginForm, RegistrationForm, EventForm, VolunteerApplicationForm

main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)
events_bp = Blueprint('events', __name__)

# Main routes
@main_bp.route('/')
def index():
    upcoming_events = Event.query.filter(Event.date >= datetime.utcnow()).order_by(Event.date).limit(6).all()
    return render_template('index.html', events=upcoming_events)

@main_bp.route('/profile')
@login_required
def profile():
    if current_user.user_type == 'elderly':
        rsvps = EventRSVP.query.filter_by(user_id=current_user.id).all()
        events = [rsvp.event for rsvp in rsvps]
        return render_template('profile.html', events=events, user_type='elderly')
    elif current_user.user_type == 'organizer':
        events = Event.query.filter_by(organizer_id=current_user.id).all()
        return render_template('profile.html', events=events, user_type='organizer')
    else:  # volunteer
        applications = VolunteerApplication.query.filter_by(volunteer_id=current_user.id).all()
        return render_template('profile.html', applications=applications, user_type='volunteer')

# Authentication routes
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(f'Welcome back, {user.first_name}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.index'))
        flash('Invalid username or password', 'danger')
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if username or email already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('auth/register.html', form=form)
        
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered. Please use a different email.', 'danger')
            return render_template('auth/register.html', form=form)
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            phone=form.phone.data,
            user_type=form.user_type.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

# Event routes
@events_bp.route('/')
def list():
    category = request.args.get('category')
    search = request.args.get('search')
    
    query = Event.query.filter(Event.date >= datetime.utcnow())
    
    if category:
        query = query.filter(Event.category == category)
    
    if search:
        query = query.filter(Event.title.contains(search) | Event.description.contains(search))
    
    events = query.order_by(Event.date).all()
    
    # Get user's RSVPs and volunteer applications if logged in
    user_rsvps = []
    user_applications = []
    if current_user.is_authenticated:
        user_rsvps = [rsvp.event_id for rsvp in EventRSVP.query.filter_by(user_id=current_user.id).all()]
        user_applications = [app.event_id for app in VolunteerApplication.query.filter_by(volunteer_id=current_user.id).all()]
    
    return render_template('events/list.html', events=events, user_rsvps=user_rsvps, user_applications=user_applications)

@events_bp.route('/<int:event_id>')
def detail(event_id):
    event = Event.query.get_or_404(event_id)
    
    user_rsvp = None
    user_application = None
    
    if current_user.is_authenticated:
        user_rsvp = EventRSVP.query.filter_by(user_id=current_user.id, event_id=event_id).first()
        user_application = VolunteerApplication.query.filter_by(volunteer_id=current_user.id, event_id=event_id).first()
    
    volunteer_form = VolunteerApplicationForm()
    
    return render_template('events/detail.html', event=event, user_rsvp=user_rsvp, 
                         user_application=user_application, volunteer_form=volunteer_form)

@events_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if current_user.user_type != 'organizer':
        flash('Only event organizers can create events.', 'danger')
        return redirect(url_for('events.list'))
    
    form = EventForm()
    if form.validate_on_submit():
        event = Event(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            date=form.date.data,
            duration_hours=form.duration_hours.data,
            location=form.location.data,
            max_participants=form.max_participants.data,
            volunteers_needed=form.volunteers_needed.data,
            organizer_id=current_user.id
        )
        
        db.session.add(event)
        db.session.commit()
        
        flash('Event created successfully!', 'success')
        return redirect(url_for('events.detail', event_id=event.id))
    
    return render_template('events/create.html', form=form)

@events_bp.route('/<int:event_id>/rsvp', methods=['POST'])
@login_required
def rsvp(event_id):
    event = Event.query.get_or_404(event_id)
    
    if current_user.user_type not in ['elderly', 'volunteer']:
        flash('Only community members can RSVP to events.', 'danger')
        return redirect(url_for('events.detail', event_id=event_id))
    
    existing_rsvp = EventRSVP.query.filter_by(user_id=current_user.id, event_id=event_id).first()
    
    if existing_rsvp:
        flash('You have already RSVP\'d to this event.', 'warning')
    elif event.is_full():
        flash('Sorry, this event is full.', 'danger')
    else:
        rsvp = EventRSVP(user_id=current_user.id, event_id=event_id)
        db.session.add(rsvp)
        db.session.commit()
        flash('RSVP successful! See you at the event.', 'success')
    
    return redirect(url_for('events.detail', event_id=event_id))

@events_bp.route('/<int:event_id>/cancel_rsvp', methods=['POST'])
@login_required
def cancel_rsvp(event_id):
    rsvp = EventRSVP.query.filter_by(user_id=current_user.id, event_id=event_id).first()
    
    if rsvp:
        db.session.delete(rsvp)
        db.session.commit()
        flash('RSVP cancelled successfully.', 'info')
    else:
        flash('No RSVP found to cancel.', 'warning')
    
    return redirect(url_for('events.detail', event_id=event_id))

@events_bp.route('/<int:event_id>/volunteer', methods=['POST'])
@login_required
def volunteer(event_id):
    if current_user.user_type != 'volunteer':
        flash('Only volunteers can apply to help with events.', 'danger')
        return redirect(url_for('events.detail', event_id=event_id))
    
    event = Event.query.get_or_404(event_id)
    existing_application = VolunteerApplication.query.filter_by(volunteer_id=current_user.id, event_id=event_id).first()
    
    if existing_application:
        flash('You have already applied to volunteer for this event.', 'warning')
    else:
        form = VolunteerApplicationForm()
        if form.validate_on_submit():
            application = VolunteerApplication(
                volunteer_id=current_user.id,
                event_id=event_id,
                message=form.message.data
            )
            db.session.add(application)
            db.session.commit()
            flash('Volunteer application submitted! The organizer will review your application.', 'success')
        else:
            flash('Please fill out the volunteer application form.', 'danger')
    
    return redirect(url_for('events.detail', event_id=event_id))
