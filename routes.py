from datetime import datetime
import random
import os
import json
import re
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, abort, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import validate_csrf, CSRFError
from app import db
from forms import LoginForm, RegistrationForm, EventForm, VolunteerApplicationForm, TwoFactorForm, ElderlyProfileForm, ChangePasswordForm, SecurityQuestionsForm, EmailLoginForm, EmailVerificationForm, RequestVerificationForm, EditProfileForm, AccountTerminationForm
from email_utils import send_verification_email, send_login_success_notification, send_termination_notification, send_event_review_notification
from unified_security_system import (
    require_user_type, require_admin, require_organizer, require_volunteer,
    require_elderly, check_resource_ownership, check_event_ownership,
    check_application_ownership, sanitize_user_input, validate_file_upload,
    log_security_event, rate_limit_per_endpoint, login_rate_limit,
    profile_edit_rate_limit, email_send_rate_limit, PasswordRotationPolicy,
    password_rotation_required, CryptographicSecurity, SQLInjectionPrevention,
    AuthenticationSecurity, SSRFPrevention, DataIntegrityValidation,
    SecurityMonitoring, OWASPSecurityValidator, session_manager,
    encryption_manager)

# Utility function for lazy imports to avoid circular dependency
def get_models():
    from models import User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward
    return User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward

# Profile blueprint for user profile management
profile_bp = Blueprint('profile', __name__, url_prefix='/profile')

main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)
events_bp = Blueprint('events', __name__)
organizer_bp = Blueprint('organizer', __name__, url_prefix='/organizer')


# Main routes
@main_bp.route('/')
def index():
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    if current_user.is_authenticated:
        if current_user.user_type == 'elderly':
            # Get elderly user's registered events
            user_events = []
            rsvps = EventRSVP.query.filter_by(user_id=current_user.id).all()
            user_events = [
                rsvp.event for rsvp in rsvps if rsvp.event.status == 'approved'
            ]

            # Get upcoming events they can join (not already registered)
            registered_event_ids = [event.id for event in user_events]
            if registered_event_ids:
                upcoming_events = Event.query.filter(
                    Event.date >= datetime.utcnow(),
                    Event.status == 'approved',
                    ~Event.id.in_(registered_event_ids)
                ).order_by(Event.date).limit(6).all()
            else:
                upcoming_events = Event.query.filter(
                    Event.date >= datetime.utcnow(),
                    Event.status == 'approved'
                ).order_by(Event.date).limit(6).all()

            return render_template('index_elderly.html',
                                   user_events=user_events,
                                   upcoming_events=upcoming_events)

        elif current_user.user_type == 'volunteer':
            # Get volunteer's applications
            volunteer_applications = VolunteerApplication.query.filter_by(
                volunteer_id=current_user.id).order_by(
                    VolunteerApplication.created_at.desc()).limit(6).all()

            # Get events needing volunteers (excluding ones they already applied to)
            applied_event_ids = [
                app.event_id for app in volunteer_applications
            ]
            if applied_event_ids:
                events_needing_volunteers = Event.query.filter(
                    Event.date >= datetime.utcnow(),
                    Event.status == 'approved',
                    Event.volunteers_needed > 0,
                    ~Event.id.in_(applied_event_ids)
                ).order_by(Event.date).limit(6).all()
            else:
                events_needing_volunteers = Event.query.filter(
                    Event.date >= datetime.utcnow(),
                    Event.status == 'approved',
                    Event.volunteers_needed > 0
                ).order_by(Event.date).limit(6).all()

            # Calculate volunteer stats
            volunteer_stats = {
                'total_applications':
                len(volunteer_applications),
                'approved_applications':
                len([
                    app for app in volunteer_applications
                    if app.status == 'approved'
                ]),
                'people_helped':
                len([
                    app for app in volunteer_applications
                    if app.status == 'approved'
                    and app.event.date < datetime.utcnow()
                ])
            }

            return render_template(
                'index_volunteer.html',
                volunteer_applications=volunteer_applications,
                events_needing_volunteers=events_needing_volunteers,
                volunteer_stats=volunteer_stats)

        elif current_user.user_type == 'organizer':
            from forms import EventForm

            # Get organizer's events
            recent_events = Event.query.filter_by(
                organizer_id=current_user.id).order_by(
                    Event.created_at.desc()).limit(6).all()

            # Calculate organizer stats
            organizer_stats = {
                'total_events':
                Event.query.filter_by(organizer_id=current_user.id).count(),
                'approved_events':
                Event.query.filter_by(organizer_id=current_user.id,
                                      status='approved').count(),
                'pending_events':
                Event.query.filter_by(organizer_id=current_user.id,
                                      status='pending').count(),
                'total_participants':
                sum([event.get_rsvp_count() for event in recent_events])
            }

            # Quick event creation form
            quick_form = EventForm()

            return render_template('index_organizer.html',
                                   recent_events=recent_events,
                                   organizer_stats=organizer_stats,
                                   quick_form=quick_form)

        elif current_user.user_type == 'admin':
            return redirect(url_for('admin.dashboard'))

    # Default for non-authenticated users
    upcoming_events = Event.query.filter(Event.date >= datetime.utcnow(),
                                         Event.status == 'approved').order_by(
                                             Event.date).limit(6).all()
    return render_template('index.html', events=upcoming_events)


@main_bp.route('/profile')
@login_required
def main_profile():
    """Redirect to appropriate dashboard based on user type"""
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    if current_user.user_type == 'elderly':
        # For elderly users, show dashboard with their events
        rsvps = EventRSVP.query.filter_by(user_id=current_user.id).all()
        events = [rsvp.event for rsvp in rsvps]
        return render_template('profile.html',
                               events=events,
                               user_type='elderly')
    elif current_user.user_type == 'organizer':
        return redirect(url_for('organizer.dashboard'))
    elif current_user.user_type == 'volunteer':
        # Redirect volunteers to a dashboard instead of profile
        return redirect(url_for('volunteer.dashboard'))
    elif current_user.user_type == 'admin':
        return redirect(url_for('admin.dashboard'))
    else:
        return redirect(url_for('main.index'))


# Authentication routes
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()
    if form.validate_on_submit():
        login_identifier = sanitize_user_input((form.nric.data or '').strip(), 100)
        user_type = request.form.get('user_type', '')

        # Comprehensive authentication validation (OWASP #7)
        auth_valid, auth_message = OWASPSecurityValidator.validate_authentication_attempt(
            login_identifier, form.password.data, user_type)
        if not auth_valid:
            OWASPSecurityValidator.log_security_event(
                'RATE_LIMIT_EXCEEDED',
                f'Login rate limit exceeded for {login_identifier}',
                severity='WARNING')
            flash('Too many login attempts. Please try again in 15 minutes.',
                  'danger')
            return render_template('auth/login.html', form=form)

        # Route based on user type selection
        if user_type == 'elderly':
            # Elderly login with NRIC
            user = User.safe_query_by_nric(login_identifier)
        elif user_type == 'other':
            # Organizer/Volunteer login with email
            if '@' in login_identifier:
                user = User.safe_query_by_email(login_identifier)
            else:
                user = User.query.filter_by(username=login_identifier).first()
        else:
            # Fallback to old logic
            if '@' in login_identifier:
                user = User.safe_query_by_email(login_identifier)
            else:
                user = User.safe_query_by_nric(login_identifier)
                if not user:
                    user = User.query.filter_by(
                        username=login_identifier).first()

        # Basic session validation
        session_valid = True

        if user and user.check_password(form.password.data):
            if user.user_type == 'elderly':
                # Initialize secure session for elderly users
                session_manager.initialize_session(user.id, user.user_type)
                session['pending_user_id'] = user.id
                return redirect(url_for('auth.two_factor'))
            elif user.user_type in ['organizer', 'volunteer']:
                # For organizers and volunteers, use email 2FA
                verification = EmailVerification.create_verification(
                    user_id=user.id, email=user.email, purpose='login')

                if send_verification_email(user.email,
                                           verification.verification_code,
                                           'login', user.get_full_name()):
                    session['pending_user_id'] = user.id
                    session['pending_login_email'] = user.email
                    session['verification_id'] = verification.id
                    flash('Please check your email for the verification code.',
                          'info')
                    return redirect(url_for('auth.verify_email_login'))
                else:
                    flash(
                        'Failed to send verification email. Please try again.',
                        'danger')
            elif user.user_type == 'admin':
                # Direct login for admin users
                login_user(user, remember=True)
                flash('Welcome back, Admin!', 'success')
                return redirect(url_for('admin.dashboard'))
        else:
            # Log failed login attempt (Logging and Monitoring)
            SecurityMonitoring.log_security_event(
                'FAILED_LOGIN',
                f'Failed login attempt for {login_identifier}')
            flash('Invalid email/NRIC or password. Please try again.',
                  'danger')

    return render_template('auth/login.html', form=form)


@auth_bp.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if 'pending_user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))

    user = User.query.get(session['pending_user_id'])
    if not user or user.user_type != 'elderly':
        session.pop('pending_user_id', None)
        flash('Invalid session. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    # Randomly select one of the three security questions
    questions = [(1, user.security_q1, user.security_a1),
                 (2, user.security_q2, user.security_a2),
                 (3, user.security_q3, user.security_a3)]

    # Filter out any empty questions
    available_questions = [(num, q, a) for num, q, a in questions if q and a]

    if not available_questions:
        session.pop('pending_user_id', None)
        flash('No security questions found. Please contact support.', 'danger')
        return redirect(url_for('auth.login'))

    # Select a random question if not already selected
    if 'security_question_number' not in session:
        question_number, selected_question, answer_hash = random.choice(
            available_questions)
        session['security_question_number'] = question_number
        session['selected_question'] = selected_question
    else:
        question_number = session['security_question_number']
        selected_question = session['selected_question']

    # Get human-readable question text
    question_mapping = {
        'birthplace': 'What is your place of birth?',
        'school': 'What was the name of your primary school?',
        'mother_maiden': 'What is your mother\'s maiden name?',
        'first_pet': 'What was the name of your first pet?',
        'childhood_friend': 'Who was your best friend in childhood?',
        'first_job': 'What was your first job?',
        'favorite_food': 'What is your favorite food?',
        'childhood_street': 'What street did you grow up on?',
        'spouse_birthplace': 'Where was your spouse born?',
        'favorite_color': 'What is your favorite color?',
        'first_car': 'What was your first car model?',
        'wedding_venue': 'Where did you get married?'
    }

    question_text = question_mapping.get(selected_question, selected_question)

    form = TwoFactorForm()
    if form.validate_on_submit():
        # Use the new hashed security answer verification
        question_number = session.get('security_question_number', 1)
        user_answer = form.security_answer.data

        if user and user.check_security_answer(question_number, user_answer):
            # 2FA successful - log in the user with remember option
            login_user(user, remember=True)
            session['user_id'] = user.id
            session.permanent = True  # Make session permanent
            welcome_name = user.get_full_name()

            # Log successful authentication (Security Monitoring)
            SecurityMonitoring.log_security_event(
                'SUCCESSFUL_LOGIN',
                f'User {user.id} completed 2FA authentication')

            flash(
                f'Welcome back, {welcome_name}! Security verification successful.',
                'success')

            # Clear 2FA session data but keep login session
            session.pop('pending_user_id', None)
            session.pop('selected_question', None)
            session.pop('correct_answer', None)
            session.pop('question_key', None)
            session.pop('security_question_number', None)

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(
                url_for('main.index'))
        else:
            # Log failed 2FA attempt
            SecurityMonitoring.log_security_event(
                'FAILED_2FA',
                f'Failed 2FA attempt for user {user.id}')
            flash('Incorrect answer. Please try again.', 'danger')

    return render_template('auth/two_factor.html',
                           form=form,
                           question=question_text,
                           user_name=user.get_full_name())


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RegistrationForm()

    # Custom validation based on user type
    if request.method == 'POST':
        user_type = form.user_type.data

        # Add conditional validation based on user type
        if user_type == 'elderly':
            # Validate elderly-specific fields
            if not form.nric.data or not form.nric.data.strip():
                form.nric.errors = list(form.nric.errors) if form.nric.errors else []
                form.nric.errors.append('NRIC is required for elderly users.')
            elif not re.match(r'^[STFG]\d{7}[A-Z]$', form.nric.data):
                form.nric.errors = list(form.nric.errors) if form.nric.errors else []
                form.nric.errors.append(
                    'Please enter valid NRIC format (e.g., S1234567A)')

            if not form.full_name.data or not form.full_name.data.strip():
                form.full_name.errors = list(form.full_name.errors) if form.full_name.errors else []
                form.full_name.errors.append(
                    'Full name is required for elderly users.')

            # Additional security validation for elderly registration (OWASP #3 Injection)
            if form.full_name.data:
                sanitized_name = form.full_name.data
                if sanitized_name != form.full_name.data:
                    form.full_name.errors = list(form.full_name.errors) if form.full_name.errors else []
                    form.full_name.errors.append(
                        'Invalid characters detected in name.')

            if not form.language_preference.data:
                form.language_preference.errors = list(form.language_preference.errors) if form.language_preference.errors else []
                form.language_preference.errors.append(
                    'Language preference is required for elderly users.')

            # Validate security questions
            if not form.security_q1.data:
                form.security_q1.errors = list(form.security_q1.errors) if form.security_q1.errors else []
                form.security_q1.errors.append('Security Question 1 is required.')
            if not form.security_a1.data or not form.security_a1.data.strip():
                form.security_a1.errors = list(form.security_a1.errors) if form.security_a1.errors else []
                form.security_a1.errors.append('Security Answer 1 is required.')

            if not form.security_q2.data:
                form.security_q2.errors = list(form.security_q2.errors) if form.security_q2.errors else []
                form.security_q2.errors.append('Security Question 2 is required.')
            if not form.security_a2.data or not form.security_a2.data.strip():
                form.security_a2.errors = list(form.security_a2.errors) if form.security_a2.errors else []
                form.security_a2.errors.append('Security Answer 2 is required.')

            if not form.security_q3.data:
                form.security_q3.errors = list(form.security_q3.errors) if form.security_q3.errors else []
                form.security_q3.errors.append('Security Question 3 is required.')
            if not form.security_a3.data or not form.security_a3.data.strip():
                form.security_a3.errors = list(form.security_a3.errors) if form.security_a3.errors else []
                form.security_a3.errors.append('Security Answer 3 is required.')

        elif user_type in ['organizer', 'volunteer']:
            # Validate organizer/volunteer fields
            if not form.first_name.data or not form.first_name.data.strip():
                form.first_name.errors = list(form.first_name.errors) if form.first_name.errors else []
                form.first_name.errors.append('First name is required for organizers and volunteers.')
            if not form.last_name.data or not form.last_name.data.strip():
                form.last_name.errors = list(form.last_name.errors) if form.last_name.errors else []
                form.last_name.errors.append('Last name is required for organizers and volunteers.')
            if not form.email.data or not form.email.data.strip():
                form.email.errors = list(form.email.errors) if form.email.errors else []
                form.email.errors.append('Email is required for organizers and volunteers.')
            elif '@' not in form.email.data:
                form.email.errors = list(form.email.errors) if form.email.errors else []
                form.email.errors.append('Please enter a valid email address.')

    if form.validate_on_submit():
        user_type = form.user_type.data

        if user_type == 'elderly':
            # Check if NRIC already exists
            if User.query.filter_by(nric=form.nric.data).first():
                flash(
                    'NRIC already registered. Please contact support if you need help.',
                    'danger')
                return render_template('auth/register.html', form=form)

            # Create elderly user
            user = User()
            user.nric = form.nric.data
            user.full_name = form.full_name.data
            user.language_preference = form.language_preference.data
            user.event_interests = ','.join(form.event_interests.data) if form.event_interests.data else ''
            user.security_q1 = form.security_q1.data
            user.security_q2 = form.security_q2.data
            user.security_q3 = form.security_q3.data
            user.user_type = 'elderly'
        else:
            # Check if username or email already exists for organizers/volunteers
            if form.email.data and User.query.filter_by(
                    email=form.email.data).first():
                flash(
                    'Email already registered. Please use a different email.',
                    'danger')
                return render_template('auth/register.html', form=form)

            # Create organizer/volunteer user
            first_name = form.first_name.data or ''
            last_name = form.last_name.data or ''
            username = form.email.data or f"{first_name.lower()}{last_name.lower()}"
            if User.query.filter_by(username=username).first():
                flash(
                    'Username already exists. Please choose a different one.',
                    'danger')
                return render_template('auth/register.html', form=form)

            user = User()
            user.username = username
            user.email = form.email.data
            user.first_name = first_name
            user.last_name = last_name
            user.phone = form.phone.data
            user.user_type = user_type

        user.set_password(form.password.data)

        # For elderly users, hash security answers and encrypt sensitive data
        if user_type == 'elderly':
            user.set_security_answers(form.security_a1.data,
                                      form.security_a2.data,
                                      form.security_a3.data)
            # Temporarily disable encryption for debugging
            # user.encrypt_sensitive_data()

        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)


@auth_bp.route('/email-login', methods=['GET', 'POST'])
def email_login():
    """Email-based login for organizers and volunteers with 2FA"""
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = EmailLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if user.user_type in ['organizer', 'volunteer']:
                # Send verification email
                verification = EmailVerification.create_verification(
                    user_id=user.id, email=user.email, purpose='login')

                if send_verification_email(user.email,
                                           verification.verification_code,
                                           'login', user.get_full_name()):
                    session['pending_user_id'] = user.id
                    session['pending_login_email'] = user.email
                    flash(
                        'A verification code has been sent to your email. Please check your inbox.',
                        'info')
                    return redirect(url_for('auth.verify_email_login'))
                else:
                    flash(
                        'Failed to send verification email. Please try again.',
                        'danger')
            else:
                flash(
                    'Email login is only for organizers and volunteers. Elderly users should use NRIC login.',
                    'warning')
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('auth/email_login.html', form=form)


@auth_bp.route('/verify-email-login', methods=['GET', 'POST'])
def verify_email_login():
    """Verify email login with 2FA code"""
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    if 'pending_user_id' not in session:
        flash('No pending login found. Please try logging in again.',
              'warning')
        return redirect(url_for('auth.email_login'))

    form = EmailVerificationForm()
    if form.validate_on_submit():
        user_id = session.get('pending_user_id')
        email = session.get('pending_login_email')

        # Find the verification record
        verification = EmailVerification.query.filter_by(
            user_id=user_id,
            email=email,
            verification_code=form.verification_code.data,
            purpose='login',
            used=False).first()

        if verification and verification.is_valid():
            # Mark verification as used
            verification.mark_used()

            # Log in the user with remember option
            user = User.query.get(user_id)
            login_user(user, remember=True)
            session['user_id'] = user.id
            session.permanent = True  # Make session permanent

            # Send success notification
            send_login_success_notification(user.email, user.get_full_name())

            # Clear session
            session.pop('pending_user_id', None)
            session.pop('pending_login_email', None)

            flash(
                f'Welcome back, {user.get_full_name()}! You have been securely logged in.',
                'success')

            # Redirect admin users directly to admin dashboard
            if user.user_type == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('main.index'))
        else:
            flash('Invalid or expired verification code. Please try again.',
                  'danger')

    return render_template('auth/email_verification.html',
                           form=form,
                           email=session.get('pending_login_email'))


@auth_bp.route('/resend-verification')
def resend_verification():
    """Resend verification code for email login"""
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    if 'pending_user_id' not in session:
        flash('No pending login found. Please try logging in again.',
              'warning')
        return redirect(url_for('auth.email_login'))

    user_id = session.get('pending_user_id')
    email = session.get('pending_login_email')

    # Create new verification code
    verification = EmailVerification.create_verification(user_id=user_id,
                                                         email=email,
                                                         purpose='login')

    user = User.query.get(user_id)
    if send_verification_email(email, verification.verification_code, 'login',
                               user.get_full_name() if user else None):
        flash('A new verification code has been sent to your email.', 'info')
    else:
        flash('Failed to send verification email. Please try again later.',
              'danger')

    return redirect(url_for('auth.verify_email_login'))


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


# Event routes
@events_bp.route('/')
def list():
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    category = request.args.get('category')
    search = request.args.get('search')

    # Only show approved events to the public
    query = Event.query.filter(Event.date >= datetime.utcnow(),
                               Event.status == 'approved')

    if category:
        query = query.filter(Event.category == category)

    if search:
        query = query.filter(
            Event.title.contains(search) | Event.description.contains(search))

    events = query.order_by(Event.date).all()

    # Get user's RSVPs and volunteer applications if logged in
    user_rsvps = []
    user_applications = []
    if current_user.is_authenticated:
        user_rsvps = [
            rsvp.event_id for rsvp in EventRSVP.query.filter_by(
                user_id=current_user.id).all()
        ]
        user_applications = [
            app.event_id for app in VolunteerApplication.query.filter_by(
                volunteer_id=current_user.id).all()
        ]

    return render_template('events/list.html',
                           events=events,
                           user_rsvps=user_rsvps,
                           user_applications=user_applications)


@events_bp.route('/<int:event_id>')
def detail(event_id):
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    event = Event.query.get_or_404(event_id)

    user_rsvp = None
    user_application = None

    if current_user.is_authenticated:
        user_rsvp = EventRSVP.query.filter_by(user_id=current_user.id,
                                              event_id=event_id).first()
        user_application = VolunteerApplication.query.filter_by(
            volunteer_id=current_user.id, event_id=event_id).first()

    volunteer_form = VolunteerApplicationForm()

    return render_template('events/detail.html',
                           event=event,
                           user_rsvp=user_rsvp,
                           user_application=user_application,
                           volunteer_form=volunteer_form)


@events_bp.route('/create', methods=['GET', 'POST'])
@login_required
@require_organizer
def create():
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()

    form = EventForm()
    if form.validate_on_submit():
        event = Event()
        event.title = form.title.data
        event.description = form.description.data
        event.category = form.category.data
        event.date = form.date.data
        event.duration_hours = form.duration_hours.data
        event.location = form.location.data
        event.max_participants = form.max_participants.data
        event.volunteers_needed = form.volunteers_needed.data
        event.organizer_id = current_user.id

        db.session.add(event)
        db.session.commit()

        flash('Event created successfully!', 'success')
        return redirect(url_for('events.detail', event_id=event.id))

    return render_template('events/create.html', form=form)


@events_bp.route('/<int:event_id>/rsvp', methods=['POST'])
@login_required
@require_user_type('elderly', 'volunteer')
def rsvp(event_id):
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    event = Event.query.get_or_404(event_id)

    existing_rsvp = EventRSVP.query.filter_by(user_id=current_user.id,
                                              event_id=event_id).first()

    if existing_rsvp:
        flash('You have already RSVP\'d to this event.', 'warning')
    elif event.is_full():
        flash('Sorry, this event is full.', 'danger')
    else:
        rsvp = EventRSVP()
        rsvp.user_id = current_user.id
        rsvp.event_id = event_id
        db.session.add(rsvp)
        db.session.commit()

        # Award points for RSVP (attendance commitment)
        if award_event_points(current_user.id, event_id, 'attendance'):
            flash(
                'RSVP successful! You earned 20 points. See you at the event.',
                'success')
        else:
            flash('RSVP successful! See you at the event.', 'success')

    return redirect(url_for('events.detail', event_id=event_id))


@events_bp.route('/<int:event_id>/cancel_rsvp', methods=['POST'])
@login_required
@require_user_type('elderly', 'volunteer')
def cancel_rsvp(event_id):
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    rsvp = EventRSVP.query.filter_by(user_id=current_user.id,
                                     event_id=event_id).first()

    # Verify user owns this RSVP
    if rsvp and not check_resource_ownership(
            rsvp.user_id, "You can only cancel your own RSVP."):
        return redirect(url_for('events.detail', event_id=event_id))

    if rsvp:
        db.session.delete(rsvp)
        db.session.commit()
        flash('RSVP cancelled successfully.', 'info')
    else:
        flash('No RSVP found to cancel.', 'warning')

    return redirect(url_for('events.detail', event_id=event_id))


@events_bp.route('/<int:event_id>/volunteer', methods=['POST'])
@login_required
@require_volunteer
def volunteer(event_id):
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()

    event = Event.query.get_or_404(event_id)
    existing_application = VolunteerApplication.query.filter_by(
        volunteer_id=current_user.id, event_id=event_id).first()

    if existing_application:
        flash('You have already applied to volunteer for this event.',
              'warning')
    else:
        form = VolunteerApplicationForm()
        if form.validate_on_submit():
            application = VolunteerApplication()
            application.volunteer_id = current_user.id
            application.event_id = event_id
            application.message = form.message.data
            db.session.add(application)
            db.session.commit()
            flash(
                'Volunteer application submitted! The organizer will review your application.',
                'success')
        else:
            flash('Please fill out the volunteer application form.', 'danger')

    return redirect(url_for('events.detail', event_id=event_id))


# Profile Management Routes
@profile_bp.route('/')
@login_required
@require_elderly
def settings():
    """Main profile settings page"""

    return render_template('profile/settings.html')


@profile_bp.route('/edit', methods=['GET', 'POST'])
@login_required
@require_elderly
def edit():
    """Edit basic profile information"""

    form = ElderlyProfileForm()

    if form.validate_on_submit():
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            filename = secure_filename(file.filename)
            # Create unique filename to prevent conflicts
            file_ext = filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_ext}"
            file_path = os.path.join('static', 'uploads', 'profile_pictures',
                                     unique_filename)

            # Save the file
            file.save(file_path)
            current_user.profile_picture = f"uploads/profile_pictures/{unique_filename}"

        # Update profile fields
        current_user.full_name = form.full_name.data
        current_user.language_preference = form.language_preference.data
        current_user.event_interests = json.dumps(
            form.event_interests.data) if form.event_interests.data else None

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile.settings'))

    # Populate form with current user data
    form.full_name.data = current_user.full_name
    form.language_preference.data = current_user.language_preference
    if current_user.event_interests:
        try:
            form.event_interests.data = json.loads(
                current_user.event_interests)
        except:
            form.event_interests.data = []

    return render_template('profile/edit.html', form=form)


@profile_bp.route('/password', methods=['GET', 'POST'])
@login_required
@require_elderly
def change_password():
    """Change user password"""

    form = ChangePasswordForm()

    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('profile.settings'))
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('profile/password.html', form=form)


@profile_bp.route('/security', methods=['GET', 'POST'])
@login_required
@require_elderly
def security_questions():
    """Update security questions with 2FA verification"""

    # Check if user has been verified for security access
    if not session.get('security_verified'):
        return redirect(url_for('profile.verify_security_access'))

    form = SecurityQuestionsForm()

    if form.validate_on_submit():
        # Verify password as additional security measure
        if not current_user.check_password(form.password_confirm.data):
            flash('Incorrect password. Please try again.', 'danger')
        else:
            current_user.security_q1 = form.security_q1.data
            current_user.security_a1 = form.security_a1.data
            current_user.security_q2 = form.security_q2.data
            current_user.security_a2 = form.security_a2.data
            current_user.security_q3 = form.security_q3.data
            current_user.security_a3 = form.security_a3.data

            db.session.commit()
            flash('Security questions updated successfully!', 'success')

            # Clear the security verification after use
            session.pop('security_verified', None)
            return redirect(url_for('profile.settings'))

    # Populate form with current data
    form.security_q1.data = current_user.security_q1
    form.security_a1.data = current_user.security_a1
    form.security_q2.data = current_user.security_q2
    form.security_a2.data = current_user.security_a2
    form.security_q3.data = current_user.security_q3
    form.security_a3.data = current_user.security_a3

    return render_template('profile/security.html', form=form)


@profile_bp.route('/verify-security', methods=['GET', 'POST'])
@login_required
def verify_security_access():
    """Verify user's identity before allowing security question changes"""
    if current_user.user_type != 'elderly':
        flash('Security verification is only available for elderly users.',
              'warning')
        return redirect(url_for('main.main_profile'))

    # Get available security questions for verification
    questions = []
    if current_user.security_q1 and current_user.security_a1:
        questions.append((current_user.security_q1, current_user.security_a1,
                          'security_q1'))
    if current_user.security_q2 and current_user.security_a2:
        questions.append((current_user.security_q2, current_user.security_a2,
                          'security_q2'))
    if current_user.security_q3 and current_user.security_a3:
        questions.append((current_user.security_q3, current_user.security_a3,
                          'security_q3'))

    if not questions:
        flash(
            'No security questions are set up. You can update them directly.',
            'info')
        session['security_verified'] = True
        return redirect(url_for('profile.security_questions'))

    # Select a random question for verification
    if 'verify_question' not in session:
        selected_question, correct_answer, question_key = random.choice(
            questions)
        session['verify_question'] = selected_question
        session['verify_answer'] = correct_answer
        session['verify_attempts'] = 0
    else:
        selected_question = session['verify_question']

    # Get human-readable question text
    question_mapping = {
        'birthplace': 'What is your place of birth?',
        'school': 'What was the name of your primary school?',
        'mother_maiden': 'What is your mother\'s maiden name?',
        'first_pet': 'What was the name of your first pet?',
        'childhood_friend': 'Who was your best friend in childhood?',
        'first_job': 'What was your first job?',
        'favorite_food': 'What is your favorite food?',
        'childhood_street': 'What street did you grow up on?',
        'spouse_birthplace': 'Where was your spouse born?',
        'favorite_color': 'What is your favorite color?',
        'first_car': 'What was your first car model?',
        'wedding_venue': 'Where did you get married?'
    }

    question_text = question_mapping.get(selected_question, selected_question)

    form = TwoFactorForm()
    if form.validate_on_submit():
        user_answer = form.security_answer.data.lower().strip(
        ) if form.security_answer.data else ''
        correct_answer = session.get(
            'verify_answer',
            '').lower().strip() if session.get('verify_answer') else ''
        attempts = session.get('verify_attempts', 0) + 1
        session['verify_attempts'] = attempts

        if user_answer == correct_answer:
            # Verification successful
            session['security_verified'] = True
            # Clear verification session data
            session.pop('verify_question', None)
            session.pop('verify_answer', None)
            session.pop('verify_attempts', None)

            flash(
                'Identity verified successfully! You can now update your security questions.',
                'success')
            return redirect(url_for('profile.security_questions'))
        else:
            if attempts >= 3:
                # Too many failed attempts - clear session and redirect
                session.pop('verify_question', None)
                session.pop('verify_answer', None)
                session.pop('verify_attempts', None)
                flash(
                    'Too many incorrect attempts. Please try again later or contact support.',
                    'danger')
                return redirect(url_for('profile.settings'))
            else:
                remaining = 3 - attempts
                flash(
                    f'Incorrect answer. You have {remaining} attempt(s) remaining.',
                    'danger')

    return render_template('profile/verify_security.html',
                           form=form,
                           question=question_text,
                           attempts=session.get('verify_attempts', 0))


@profile_bp.route('/delete-picture', methods=['POST'])
@login_required
@require_elderly
def delete_picture():
    """Delete profile picture"""

    if current_user.profile_picture:
        # Delete the file from filesystem
        file_path = os.path.join('static', current_user.profile_picture)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Remove from database
        current_user.profile_picture = None
        db.session.commit()
        flash('Profile picture removed successfully!', 'success')
    else:
        flash('No profile picture to delete.', 'warning')

    return redirect(url_for('profile.edit'))


# Organizer Dashboard Routes
@organizer_bp.route('/dashboard')
@login_required
@require_organizer
def dashboard():
    """Organizer dashboard with event management"""
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()

    # Get organizer's events with different statuses
    pending_events = Event.query.filter_by(organizer_id=current_user.id,
                                           status='pending').order_by(
                                               Event.created_at.desc()).all()
    approved_events = Event.query.filter_by(organizer_id=current_user.id,
                                            status='approved').order_by(
                                                Event.date).all()
    rejected_events = Event.query.filter_by(organizer_id=current_user.id,
                                            status='rejected').order_by(
                                                Event.created_at.desc()).all()

    # Get statistics
    total_events = Event.query.filter_by(organizer_id=current_user.id).count()
    total_participants = db.session.query(db.func.count(
        EventRSVP.id)).join(Event).filter(
            Event.organizer_id == current_user.id, Event.status
            == 'approved').scalar() or 0
    total_volunteers = db.session.query(db.func.count(
        VolunteerApplication.id)).join(Event).filter(
            Event.organizer_id == current_user.id, VolunteerApplication.status
            == 'approved').scalar() or 0

    return render_template('organizer/dashboard.html',
                           pending_events=pending_events,
                           approved_events=approved_events,
                           rejected_events=rejected_events,
                           total_events=total_events,
                           total_participants=total_participants,
                           total_volunteers=total_volunteers)


@organizer_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@require_organizer
def organizer_profile():
    """Organizer profile management"""

    form = EditProfileForm()

    if form.validate_on_submit():
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            if file.filename:
                # Create uploads directory if it doesn't exist
                upload_dir = os.path.join('static', 'uploads',
                                          'profile_pictures')
                os.makedirs(upload_dir, exist_ok=True)

                # Generate unique filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{current_user.id}_{timestamp}.png"
                file_path = os.path.join(upload_dir, filename)

                # Delete old profile picture if exists
                if current_user.profile_picture:
                    old_file_path = os.path.join('static',
                                                 current_user.profile_picture)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)

                # Save new picture
                file.save(file_path)
                current_user.profile_picture = f"uploads/profile_pictures/{filename}"

        # Update profile information
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.phone = form.phone.data

        # Update email if changed
        if form.email.data != current_user.email:
            current_user.email = form.email.data
            current_user.username = form.email.data  # Update username to match email

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('organizer.profile'))

    # Pre-populate form with current data
    form.first_name.data = current_user.first_name
    form.last_name.data = current_user.last_name
    form.email.data = current_user.email
    form.phone.data = current_user.phone

    return render_template('organizer/profile.html',
                           form=form,
                           user=current_user)


@organizer_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@require_organizer
def change_password():
    """Change organizer password"""

    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('organizer.profile'))
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('organizer/change_password.html', form=form)


@organizer_bp.route('/delete-picture', methods=['POST'])
@login_required
@require_organizer
def delete_picture():
    """Delete organizer profile picture"""

    if current_user.profile_picture:
        # Delete the file from filesystem
        file_path = os.path.join('static', current_user.profile_picture)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Remove from database
        current_user.profile_picture = None
        db.session.commit()
        flash('Profile picture removed successfully!', 'success')
    else:
        flash('No profile picture to delete.', 'warning')

    return redirect(url_for('organizer.profile'))


# Volunteer Blueprint - Profile Management
volunteer_bp = Blueprint('volunteer', __name__, url_prefix='/volunteer')


@volunteer_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@require_volunteer
def volunteer_profile():
    """Volunteer profile management"""

    form = EditProfileForm()

    if form.validate_on_submit():
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            if file.filename:
                # Create uploads directory if it doesn't exist
                upload_dir = os.path.join('static', 'uploads',
                                          'profile_pictures')
                os.makedirs(upload_dir, exist_ok=True)

                # Generate unique filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{current_user.id}_{timestamp}.png"
                file_path = os.path.join(upload_dir, filename)

                # Delete old profile picture if exists
                if current_user.profile_picture:
                    old_file_path = os.path.join('static',
                                                 current_user.profile_picture)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)

                # Save new picture
                file.save(file_path)
                current_user.profile_picture = f"uploads/profile_pictures/{filename}"

        # Update profile information
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.phone = form.phone.data

        # Update email if changed
        if form.email.data != current_user.email:
            current_user.email = form.email.data
            current_user.username = form.email.data  # Update username to match email

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('volunteer.profile'))

    # Pre-populate form with current data
    form.first_name.data = current_user.first_name
    form.last_name.data = current_user.last_name
    form.email.data = current_user.email
    form.phone.data = current_user.phone

    return render_template('volunteer/profile.html',
                           form=form,
                           user=current_user)


@volunteer_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@require_volunteer
def change_password():
    """Change volunteer password"""

    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('volunteer.profile'))
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('volunteer/change_password.html', form=form)


@volunteer_bp.route('/delete-picture', methods=['POST'])
@login_required
@require_volunteer
def delete_picture():
    """Delete volunteer profile picture"""

    if current_user.profile_picture:
        # Delete the file from filesystem
        file_path = os.path.join('static', current_user.profile_picture)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Remove from database
        current_user.profile_picture = None
        db.session.commit()
        flash('Profile picture removed successfully!', 'success')
    else:
        flash('No profile picture to delete.', 'warning')

    return redirect(url_for('volunteer.profile'))


@volunteer_bp.route('/dashboard')
@login_required
@require_volunteer
def dashboard():
    """Volunteer dashboard"""
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()

    # Get volunteer's applications and statistics
    applications = VolunteerApplication.query.filter_by(
        volunteer_id=current_user.id).all()
    total_applications = len(applications)
    approved_applications = len(
        [app for app in applications if app.status == 'approved'])
    pending_applications = len(
        [app for app in applications if app.status == 'pending'])

    # Get available volunteer opportunities
    available_events = Event.query.filter(
        Event.date >= datetime.utcnow(), Event.status == 'approved',
        Event.volunteers_needed > 0).order_by(Event.date).limit(6).all()

    return render_template('volunteer/dashboard.html',
                           applications=applications,
                           total_applications=total_applications,
                           approved_applications=approved_applications,
                           pending_applications=pending_applications,
                           available_events=available_events)


# Admin Blueprint - Database Management
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/dashboard')
@login_required
@require_admin
def dashboard():
    """Admin dashboard with database management"""
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()

    # Get database statistics
    total_users = User.query.count()
    elderly_users = User.query.filter_by(user_type='elderly').count()
    organizers = User.query.filter_by(user_type='organizer').count()
    volunteers = User.query.filter_by(user_type='volunteer').count()
    admins = User.query.filter_by(user_type='admin').count()

    total_events = Event.query.count()
    pending_events = Event.query.filter_by(status='pending').count()
    approved_events = Event.query.filter_by(status='approved').count()
    rejected_events = Event.query.filter_by(status='rejected').count()

    total_rsvps = EventRSVP.query.count()
    total_volunteer_apps = VolunteerApplication.query.count()
    pending_volunteer_apps = VolunteerApplication.query.filter_by(
        status='pending').count()

    # Recent activities
    recent_users = User.query.order_by(User.id.desc()).limit(5).all()
    recent_events = Event.query.order_by(
        Event.created_at.desc()).limit(5).all()
    pending_events_list = Event.query.filter_by(status='pending').order_by(
        Event.created_at.desc()).limit(10).all()

    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           elderly_users=elderly_users,
                           organizers=organizers,
                           volunteers=volunteers,
                           admins=admins,
                           total_events=total_events,
                           pending_events=pending_events,
                           approved_events=approved_events,
                           rejected_events=rejected_events,
                           total_rsvps=total_rsvps,
                           total_volunteer_apps=total_volunteer_apps,
                           pending_volunteer_apps=pending_volunteer_apps,
                           recent_users=recent_users,
                           recent_events=recent_events,
                           pending_events_list=pending_events_list)


@admin_bp.route('/users')
@login_required
@require_admin
def users():
    """Admin user management"""

    page = request.args.get('page', 1, type=int)
    user_type_filter = request.args.get('type', 'all')
    search = request.args.get('search', '')

    query = User.query

    if user_type_filter != 'all':
        query = query.filter_by(user_type=user_type_filter)

    if search:
        query = query.filter(
            db.or_(User.first_name.contains(search),
                   User.last_name.contains(search),
                   User.full_name.contains(search),
                   User.email.contains(search)))

    users = query.order_by(User.id.desc()).paginate(page=page,
                                                    per_page=20,
                                                    error_out=False)

    return render_template('admin/users.html',
                           users=users,
                           user_type_filter=user_type_filter,
                           search=search)


@admin_bp.route('/events')
@login_required
@require_admin
def events():
    """Admin event management"""

    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    search = request.args.get('search', '')

    query = Event.query

    if status_filter != 'all':
        query = query.filter_by(status=status_filter)

    if search:
        query = query.filter(
            db.or_(Event.title.contains(search),
                   Event.description.contains(search),
                   Event.location.contains(search)))

    events = query.order_by(Event.created_at.desc()).paginate(page=page,
                                                              per_page=20,
                                                              error_out=False)

    return render_template('admin/events.html',
                           events=events,
                           status_filter=status_filter,
                           search=search)


@admin_bp.route('/event/<int:event_id>/review', methods=['GET', 'POST'])
@login_required
@require_admin
def review_event(event_id):
    """Review an event with admin remarks"""
    from forms import EventReviewForm
    from datetime import datetime

    event = Event.query.get_or_404(event_id)
    form = EventReviewForm()

    if form.validate_on_submit():
        # Update event status and add admin remarks
        event.status = form.action.data
        event.admin_remarks = form.admin_remarks.data
        event.reviewed_by = current_user.id
        event.reviewed_at = datetime.utcnow()

        db.session.commit()

        # Send notification email to organizer
        try:
            organizer = User.query.get(event.organizer_id)
            if organizer and organizer.email:
                send_event_review_notification(organizer.email,
                                               organizer.get_full_name(),
                                               event.title, form.action.data,
                                               form.admin_remarks.data)
        except Exception as e:
            flash(
                f'Event {form.action.data} but email notification failed: {str(e)}',
                'warning')

        action_text = 'approved' if form.action.data == 'approved' else 'rejected'
        flash(f'Event "{event.title}" has been {action_text} with remarks.',
              'success')
        return redirect(url_for('admin.events'))

    return render_template('admin/review_event.html', form=form, event=event)


@admin_bp.route('/event/<int:event_id>/approve', methods=['POST'])
@login_required
@require_admin
def approve_event(event_id):
    """Quick approve an event (legacy route)"""
    from datetime import datetime

    event = Event.query.get_or_404(event_id)
    event.status = 'approved'
    event.reviewed_by = current_user.id
    event.reviewed_at = datetime.utcnow()
    db.session.commit()

    flash(f'Event "{event.title}" has been approved.', 'success')
    return redirect(request.referrer or url_for('admin.events'))


@admin_bp.route('/event/<int:event_id>/reject', methods=['POST'])
@login_required
@require_admin
def reject_event(event_id):
    """Quick reject an event (legacy route)"""
    from datetime import datetime

    event = Event.query.get_or_404(event_id)
    event.status = 'rejected'
    event.reviewed_by = current_user.id
    event.reviewed_at = datetime.utcnow()
    db.session.commit()

    flash(f'Event "{event.title}" has been rejected.', 'success')
    return redirect(request.referrer or url_for('admin.events'))


@admin_bp.route('/user/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@require_admin
def toggle_user_status(user_id):
    """Toggle user active status"""

    user = User.query.get_or_404(user_id)
    if user.user_type == 'admin' and user.id != current_user.id:
        flash('Cannot modify other admin accounts.', 'danger')
        return redirect(request.referrer or url_for('admin.users'))

    # Toggle active status
    user.account_active = not user.account_active
    db.session.commit()

    status = 'activated' if user.account_active else 'deactivated'
    flash(f'User {user.get_full_name()} has been {status}.', 'success')
    return redirect(request.referrer or url_for('admin.users'))


@admin_bp.route('/create-admin', methods=['GET', 'POST'])
@login_required
@require_admin
def create_admin():
    """Create new admin account"""

    form = EditProfileForm()

    if form.validate_on_submit():
        # Check if email already exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return render_template('admin/create_admin.html', form=form)

        # Create admin user
        admin_user = User(username=form.email.data,
                          email=form.email.data,
                          first_name=form.first_name.data,
                          last_name=form.last_name.data,
                          phone=form.phone.data,
                          user_type='admin')
        admin_user.set_password('admin123')  # Default password

        db.session.add(admin_user)
        db.session.commit()

        flash(
            f'Admin account created for {admin_user.get_full_name()}. Default password: admin123',
            'success')
        return redirect(url_for('admin.users'))

    return render_template('admin/create_admin.html', form=form)


@organizer_bp.route('/create-event', methods=['GET', 'POST'])
@login_required
@require_organizer
def create_event():
    """Create a new event"""

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
            organizer_id=current_user.id,
            status='pending'  # Events start as pending for approval
        )
        db.session.add(event)
        db.session.commit()
        flash(
            'Event created successfully! It will be reviewed and approved before being visible to participants.',
            'success')
        return redirect(url_for('organizer.dashboard'))

    return render_template('organizer/create_event.html', form=form)


@organizer_bp.route('/event/<int:event_id>')
@login_required
@require_organizer
def event_detail(event_id):
    """View detailed event information and manage participants/volunteers"""
    event = Event.query.get_or_404(event_id)

    # Ensure the organizer owns this event (or admin access)
    check_event_ownership(event.organizer_id)

    # Get participants and volunteers
    rsvps = EventRSVP.query.filter_by(event_id=event_id).all()
    participants = [rsvp.user for rsvp in rsvps]

    volunteer_apps = VolunteerApplication.query.filter_by(
        event_id=event_id).all()

    return render_template('organizer/event_detail.html',
                           event=event,
                           participants=participants,
                           volunteer_applications=volunteer_apps)


@organizer_bp.route('/volunteer/<int:app_id>/approve', methods=['POST'])
@login_required
@require_organizer
def approve_volunteer(app_id):
    """Approve a volunteer application"""
    app = VolunteerApplication.query.get_or_404(app_id)

    # Verify organizer owns the event
    check_event_ownership(app.event.organizer_id)

    app.status = 'approved'
    db.session.commit()

    # Award points to volunteer for approved application
    if award_event_points(app.volunteer_id, app.event_id, 'volunteer'):
        flash(
            f'Volunteer application from {app.volunteer.get_full_name()} has been approved! They earned 30 points.',
            'success')
    else:
        flash(
            f'Volunteer application from {app.volunteer.get_full_name()} has been approved!',
            'success')

    return redirect(url_for('organizer.event_detail', event_id=app.event_id))


@organizer_bp.route('/volunteer/<int:app_id>/reject', methods=['POST'])
@login_required
@require_organizer
def reject_volunteer(app_id):
    """Reject a volunteer application"""

    app = VolunteerApplication.query.get_or_404(app_id)

    # Verify organizer owns the event
    check_event_ownership(app.event.organizer_id)

    app.status = 'rejected'
    db.session.commit()
    flash(
        f'Volunteer application from {app.volunteer.get_full_name()} has been rejected.',
        'info')

    return redirect(url_for('organizer.event_detail', event_id=app.event_id))


@organizer_bp.route('/event/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
@require_organizer
def edit_event(event_id):
    """Edit an existing event"""
    event = Event.query.get_or_404(event_id)

    # Ensure the organizer owns this event
    check_event_ownership(event.organizer_id)

    form = EventForm(obj=event)
    if form.validate_on_submit():
        form.populate_obj(event)
        # Reset status to pending if event was previously rejected
        if event.status == 'rejected':
            event.status = 'pending'
            flash('Event updated and resubmitted for approval!', 'success')
        else:
            flash('Event updated successfully!', 'success')

        db.session.commit()
        return redirect(url_for('organizer.dashboard'))

    return render_template('organizer/edit_event.html', form=form, event=event)


@organizer_bp.route('/event/<int:event_id>/delete', methods=['POST'])
@login_required
@require_organizer
def delete_event(event_id):
    """Delete an event"""
    event = Event.query.get_or_404(event_id)

    # Ensure the organizer owns this event
    check_event_ownership(event.organizer_id)

    # Delete related records first
    EventRSVP.query.filter_by(event_id=event_id).delete()
    VolunteerApplication.query.filter_by(event_id=event_id).delete()

    db.session.delete(event)
    db.session.commit()

    flash('Event deleted successfully!', 'success')
    return redirect(url_for('organizer.dashboard'))


@admin_bp.route('/terminate-account/<int:user_id>', methods=['GET', 'POST'])
@login_required
@require_admin
def terminate_account(user_id):
    """Terminate a user account with reasons"""
    user = User.query.get_or_404(user_id)

    # Prevent admin from terminating their own account
    if user.id == current_user.id:
        log_security_event('admin_self_termination_attempt', current_user.id)
        flash('You cannot terminate your own account.', 'warning')
        return redirect(url_for('admin.users'))

    form = AccountTerminationForm()

    if form.validate_on_submit():
        # Prepare termination details
        reasons = form.termination_reasons.data
        custom_reason = form.custom_reason.data.strip(
        ) if form.custom_reason.data else ""

        reason_text = []
        reason_labels = {
            'inactive': 'Account Inactive',
            'policy_violation': 'Policy Violation',
            'spam': 'Spam/Abuse',
            'inappropriate_behavior': 'Inappropriate Behavior',
            'security_concern': 'Security Concern',
            'duplicate_account': 'Duplicate Account',
            'user_request': 'User Requested Deletion',
            'data_cleanup': 'Data Cleanup/Maintenance'
        }

        for reason in reasons:
            if reason in reason_labels:
                reason_text.append(reason_labels[reason])

        # Send termination notification email
        if user.email:
            try:
                send_termination_notification(user.email,
                                              user.get_first_name(),
                                              reason_text, custom_reason)
            except Exception as e:
                flash(
                    f'Account terminated but email notification failed: {str(e)}',
                    'warning')

        # Delete related data
        if user.user_type == 'elderly':
            # Delete RSVPs
            EventRSVP.query.filter_by(user_id=user.id).delete()
        elif user.user_type == 'organizer':
            # Delete events and related data
            events = Event.query.filter_by(organizer_id=user.id).all()
            for event in events:
                EventRSVP.query.filter_by(event_id=event.id).delete()
                VolunteerApplication.query.filter_by(
                    event_id=event.id).delete()
            Event.query.filter_by(organizer_id=user.id).delete()
        elif user.user_type == 'volunteer':
            # Delete volunteer applications
            VolunteerApplication.query.filter_by(volunteer_id=user.id).delete()

        # Delete email verifications
        EmailVerification.query.filter_by(user_id=user.id).delete()

        # Delete profile picture if exists
        if user.profile_picture:
            file_path = os.path.join('static', user.profile_picture)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass  # File deletion failure shouldn't stop account termination

        # Delete the user
        username = user.get_full_name() or user.username or user.email
        db.session.delete(user)
        db.session.commit()

        flash(f'Account for {username} has been successfully terminated.',
              'success')
        return redirect(url_for('admin.users'))

    return render_template('admin/terminate_account.html',
                           form=form,
                           user=user)


# ========== REWARD SYSTEM ROUTES ==========


@main_bp.route('/rewards')
@login_required
def rewards():
    """Display available vouchers and user's redeemed vouchers"""
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    # Debug logging
    current_app.logger.info(
        f"Rewards access attempt - User authenticated: {current_user.is_authenticated}, User ID: {current_user.id if current_user.is_authenticated else 'None'}, User type: {current_user.user_type if current_user.is_authenticated else 'None'}"
    )

    # Check if user has access to rewards
    if not current_user.is_authenticated or current_user.user_type not in [
            'elderly', 'volunteer'
    ]:
        flash(
            'Access denied. Rewards are only available for community members and volunteers.',
            'warning')
        current_app.logger.warning(
            f"Rewards access denied - User authenticated: {current_user.is_authenticated}, User type: {current_user.user_type if current_user.is_authenticated else 'None'}"
        )
        return redirect(url_for('main.index'))

    try:
        # Get available vouchers
        vouchers = RewardVoucher.query.filter_by(is_active=True).order_by(
            RewardVoucher.points_required).all()

        # Get user's redeemed vouchers
        redeemed_vouchers = UserReward.query.filter_by(
            user_id=current_user.id).order_by(
                UserReward.redeemed_at.desc()).all()

        current_app.logger.info(
            f"Rewards page loaded successfully for user {current_user.id}")
        return render_template('rewards.html',
                               vouchers=vouchers,
                               redeemed_vouchers=redeemed_vouchers)
    except Exception as e:
        current_app.logger.error(f"Error loading rewards page: {str(e)}")
        flash('Error loading rewards page. Please try again.', 'error')
        return redirect(url_for('main.index'))


@main_bp.route('/redeem-voucher', methods=['POST'])
@login_required
def redeem_voucher():
    """Redeem a voucher with user's points"""
    User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward = get_models()
    
    # Check if user has access to rewards
    if not current_user.is_authenticated or current_user.user_type not in [
            'elderly', 'volunteer'
    ]:
        flash(
            'Access denied. Only community members and volunteers can redeem vouchers.',
            'warning')
        return redirect(url_for('main.index'))

    try:
        # Skip CSRF validation for this endpoint temporarily
        voucher_id = request.form.get('voucher_id')
        if not voucher_id:
            flash('Invalid voucher selection.', 'error')
            return redirect(url_for('main.rewards'))

        # Redeem the voucher
        redemption, message = UserReward.redeem_voucher(
            current_user.id, voucher_id)

        if redemption:
            flash(
                f'Voucher redeemed successfully! Your redemption code is: {redemption.redemption_code}',
                'success')

            # Log the redemption for security monitoring
            log_security_event('VOUCHER_REDEEMED',
                               user_id=current_user.id,
                               details={
                                   'voucher_id': voucher_id,
                                   'points_spent': redemption.points_spent,
                                   'redemption_code':
                                   redemption.redemption_code
                               })
        else:
            flash(message, 'error')

        return redirect(url_for('main.rewards'))

    except Exception as e:
        flash('Error processing voucher redemption. Please try again.',
              'error')
        return redirect(url_for('main.rewards'))


def award_event_points(user_id, event_id, participation_type='attendance'):
    """Award points to a user for event participation"""
    try:
        user = User.query.get(user_id)
        if not user or user.user_type not in ['elderly', 'volunteer']:
            return False

        # Point values based on participation type
        point_values = {
            'attendance': 20,  # Elderly attending events
            'volunteer': 30,  # Volunteers helping at events
            'completion': 10,  # Completing event activities
            'setup': 10,  # Helping with setup/cleanup
            'training': 15  # Completing volunteer training
        }

        points = point_values.get(participation_type, 10)

        # Award the points
        success = user.award_points(
            points, f"Event participation: {participation_type}")

        if success:
            # Log the point award
            log_security_event('POINTS_AWARDED',
                               user_id=user_id,
                               details={
                                   'event_id': event_id,
                                   'participation_type': participation_type,
                                   'points_awarded': points,
                                   'total_points': user.reward_points
                               })

        return success

    except Exception as e:
        return False
