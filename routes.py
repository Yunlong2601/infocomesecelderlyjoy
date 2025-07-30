from datetime import datetime
import random
import os
import json
import re
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from models import User, Event, EventRSVP, VolunteerApplication, EmailVerification
from forms import LoginForm, RegistrationForm, EventForm, VolunteerApplicationForm, TwoFactorForm, ElderlyProfileForm, ChangePasswordForm, SecurityQuestionsForm, EmailLoginForm, EmailVerificationForm, RequestVerificationForm
from email_utils import send_verification_email, send_login_success_notification

# Profile blueprint for user profile management
profile_bp = Blueprint('profile', __name__, url_prefix='/profile')

main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)
events_bp = Blueprint('events', __name__)
organizer_bp = Blueprint('organizer', __name__, url_prefix='/organizer')

# Main routes
@main_bp.route('/')
def index():
    # Only show approved events to the public
    upcoming_events = Event.query.filter(
        Event.date >= datetime.utcnow(),
        Event.status == 'approved'
    ).order_by(Event.date).limit(6).all()
    return render_template('index.html', events=upcoming_events)

@main_bp.route('/profile')
@login_required
def profile():
    if current_user.user_type == 'elderly':
        rsvps = EventRSVP.query.filter_by(user_id=current_user.id).all()
        events = [rsvp.event for rsvp in rsvps]
        return render_template('profile.html', events=events, user_type='elderly')
    elif current_user.user_type == 'organizer':
        return redirect(url_for('organizer.dashboard'))
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
        login_identifier = form.nric.data.strip()
        
        # Check if it's an email (contains @) or NRIC/username
        if '@' in login_identifier:
            # Email login - find user by email
            user = User.query.filter_by(email=login_identifier).first()
        else:
            # NRIC/username login - try NRIC first (elderly), then username (organizers/volunteers)
            user = User.query.filter_by(nric=login_identifier).first()
            if not user:
                user = User.query.filter_by(username=login_identifier).first()
        
        if user and user.check_password(form.password.data):
            if user.user_type == 'elderly':
                # For elderly users, use 2FA with security questions
                session['pending_user_id'] = user.id
                return redirect(url_for('auth.two_factor'))
            else:
                # For organizers and volunteers, use email 2FA
                verification = EmailVerification.create_verification(
                    user_id=user.id,
                    email=user.email,
                    purpose='login'
                )
                
                if send_verification_email(user.email, verification.verification_code, 'login'):
                    session['pending_user_id'] = user.id
                    session['verification_id'] = verification.id
                    flash('Please check your email for the verification code.', 'info')
                    return redirect(url_for('auth.email_verification'))
                else:
                    flash('Failed to send verification email. Please try again.', 'danger')
        else:
            flash('Invalid email/NRIC or password. Please try again.', 'danger')
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
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
    questions = [
        (user.security_q1, user.security_a1, 'security_q1'),
        (user.security_q2, user.security_a2, 'security_q2'), 
        (user.security_q3, user.security_a3, 'security_q3')
    ]
    
    # Filter out any empty questions
    available_questions = [(q, a, key) for q, a, key in questions if q and a]
    
    if not available_questions:
        session.pop('pending_user_id', None)
        flash('No security questions found. Please contact support.', 'danger')
        return redirect(url_for('auth.login'))
    
    # Select a random question if not already selected
    if 'selected_question' not in session:
        selected_question, correct_answer, question_key = random.choice(available_questions)
        session['selected_question'] = selected_question
        session['correct_answer'] = correct_answer
        session['question_key'] = question_key
    else:
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
        user_answer = form.security_answer.data.lower().strip() if form.security_answer.data else ''
        correct_answer = session.get('correct_answer', '').lower().strip() if session.get('correct_answer') else ''
        
        if user_answer == correct_answer:
            # 2FA successful - log in the user
            login_user(user)
            welcome_name = user.get_full_name()
            flash(f'Welcome back, {welcome_name}! Security verification successful.', 'success')
            
            # Clear session data
            session.pop('pending_user_id', None)
            session.pop('selected_question', None)
            session.pop('correct_answer', None)
            session.pop('question_key', None)
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.index'))
        else:
            flash('Incorrect answer. Please try again.', 'danger')
    
    return render_template('auth/two_factor.html', form=form, question=question_text, user_name=user.get_full_name())

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
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
                form.nric.errors.append('NRIC is required for elderly users.')
            elif not re.match(r'^[STFG]\d{7}[A-Z]$', form.nric.data):
                form.nric.errors.append('Please enter valid NRIC format (e.g., S1234567A)')
            
            if not form.full_name.data or not form.full_name.data.strip():
                form.full_name.errors.append('Full name is required for elderly users.')
            
            if not form.language_preference.data:
                form.language_preference.errors.append('Language preference is required for elderly users.')
            
            # Validate security questions
            if not form.security_q1.data:
                form.security_q1.errors.append('Security Question 1 is required.')
            if not form.security_a1.data or not form.security_a1.data.strip():
                form.security_a1.errors.append('Security Answer 1 is required.')
            
            if not form.security_q2.data:
                form.security_q2.errors.append('Security Question 2 is required.')
            if not form.security_a2.data or not form.security_a2.data.strip():
                form.security_a2.errors.append('Security Answer 2 is required.')
            
            if not form.security_q3.data:
                form.security_q3.errors.append('Security Question 3 is required.')
            if not form.security_a3.data or not form.security_a3.data.strip():
                form.security_a3.errors.append('Security Answer 3 is required.')
                
        elif user_type in ['organizer', 'volunteer']:
            # Validate organizer/volunteer fields
            if not form.first_name.data or not form.first_name.data.strip():
                form.first_name.errors.append('First name is required for organizers and volunteers.')
            if not form.last_name.data or not form.last_name.data.strip():
                form.last_name.errors.append('Last name is required for organizers and volunteers.')
            if not form.email.data or not form.email.data.strip():
                form.email.errors.append('Email is required for organizers and volunteers.')
            elif '@' not in form.email.data:
                form.email.errors.append('Please enter a valid email address.')
    
    if form.validate_on_submit():
        user_type = form.user_type.data
        
        if user_type == 'elderly':
            # Check if NRIC already exists
            if User.query.filter_by(nric=form.nric.data).first():
                flash('NRIC already registered. Please contact support if you need help.', 'danger')
                return render_template('auth/register.html', form=form)
            
            # Create elderly user
            user = User(
                nric=form.nric.data,
                full_name=form.full_name.data,
                language_preference=form.language_preference.data,
                event_interests=','.join(form.event_interests.data) if form.event_interests.data else '',
                security_q1=form.security_q1.data,
                security_a1=form.security_a1.data.lower().strip() if form.security_a1.data else '',
                security_q2=form.security_q2.data,
                security_a2=form.security_a2.data.lower().strip() if form.security_a2.data else '',
                security_q3=form.security_q3.data,
                security_a3=form.security_a3.data.lower().strip() if form.security_a3.data else '',
                user_type='elderly'
            )
        else:
            # Check if username or email already exists for organizers/volunteers
            if form.email.data and User.query.filter_by(email=form.email.data).first():
                flash('Email already registered. Please use a different email.', 'danger')
                return render_template('auth/register.html', form=form)
            
            # Create organizer/volunteer user
            first_name = form.first_name.data or ''
            last_name = form.last_name.data or ''
            username = form.email.data or f"{first_name.lower()}{last_name.lower()}"
            if User.query.filter_by(username=username).first():
                flash('Username already exists. Please choose a different one.', 'danger')
                return render_template('auth/register.html', form=form)
            
            user = User(
                username=username,
                email=form.email.data,
                first_name=first_name,
                last_name=last_name,
                phone=form.phone.data,
                user_type=user_type
            )
        
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', form=form)

@auth_bp.route('/email-login', methods=['GET', 'POST'])
def email_login():
    """Email-based login for organizers and volunteers with 2FA"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = EmailLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if user.user_type in ['organizer', 'volunteer']:
                # Send verification email
                verification = EmailVerification.create_verification(
                    user_id=user.id,
                    email=user.email,
                    purpose='login'
                )
                
                if send_verification_email(user.email, verification.verification_code, 'login'):
                    session['pending_user_id'] = user.id
                    session['pending_login_email'] = user.email
                    flash('A verification code has been sent to your email. Please check your inbox.', 'info')
                    return redirect(url_for('auth.verify_email_login'))
                else:
                    flash('Failed to send verification email. Please try again.', 'danger')
            else:
                flash('Email login is only for organizers and volunteers. Elderly users should use NRIC login.', 'warning')
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    
    return render_template('auth/email_login.html', form=form)

@auth_bp.route('/verify-email-login', methods=['GET', 'POST'])
def verify_email_login():
    """Verify email login with 2FA code"""
    if 'pending_user_id' not in session:
        flash('No pending login found. Please try logging in again.', 'warning')
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
            used=False
        ).first()
        
        if verification and verification.is_valid():
            # Mark verification as used
            verification.mark_used()
            
            # Log in the user
            user = User.query.get(user_id)
            login_user(user)
            
            # Send success notification
            send_login_success_notification(user.email, user.get_full_name())
            
            # Clear session
            session.pop('pending_user_id', None)
            session.pop('pending_login_email', None)
            
            flash(f'Welcome back, {user.get_full_name()}! You have been securely logged in.', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid or expired verification code. Please try again.', 'danger')
    
    return render_template('auth/email_verification.html', form=form, email=session.get('pending_login_email'))

@auth_bp.route('/resend-verification')
def resend_verification():
    """Resend verification code for email login"""
    if 'pending_user_id' not in session:
        flash('No pending login found. Please try logging in again.', 'warning')
        return redirect(url_for('auth.email_login'))
    
    user_id = session.get('pending_user_id')
    email = session.get('pending_login_email')
    
    # Create new verification code
    verification = EmailVerification.create_verification(
        user_id=user_id,
        email=email,
        purpose='login'
    )
    
    if send_verification_email(email, verification.verification_code, 'login'):
        flash('A new verification code has been sent to your email.', 'info')
    else:
        flash('Failed to send verification email. Please try again later.', 'danger')
    
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
    category = request.args.get('category')
    search = request.args.get('search')
    
    # Only show approved events to the public
    query = Event.query.filter(Event.date >= datetime.utcnow(), Event.status == 'approved')
    
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

# Profile Management Routes
@profile_bp.route('/')
@login_required
def settings():
    """Main profile settings page"""
    if current_user.user_type != 'elderly':
        flash('Profile management is only available for elderly users.', 'warning')
        return redirect(url_for('main.profile'))
    
    return render_template('profile/settings.html')

@profile_bp.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    """Edit basic profile information"""
    if current_user.user_type != 'elderly':
        flash('Profile editing is only available for elderly users.', 'warning')
        return redirect(url_for('main.profile'))
    
    form = ElderlyProfileForm()
    
    if form.validate_on_submit():
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            filename = secure_filename(file.filename)
            # Create unique filename to prevent conflicts
            file_ext = filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_ext}"
            file_path = os.path.join('static', 'uploads', 'profile_pictures', unique_filename)
            
            # Save the file
            file.save(file_path)
            current_user.profile_picture = f"uploads/profile_pictures/{unique_filename}"
        
        # Update profile fields
        current_user.full_name = form.full_name.data
        current_user.language_preference = form.language_preference.data
        current_user.event_interests = json.dumps(form.event_interests.data) if form.event_interests.data else None
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile.settings'))
    
    # Populate form with current user data
    form.full_name.data = current_user.full_name
    form.language_preference.data = current_user.language_preference
    if current_user.event_interests:
        try:
            form.event_interests.data = json.loads(current_user.event_interests)
        except:
            form.event_interests.data = []
    
    return render_template('profile/edit.html', form=form)

@profile_bp.route('/password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    if current_user.user_type != 'elderly':
        flash('Password change is only available for elderly users.', 'warning')
        return redirect(url_for('main.profile'))
    
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
def security_questions():
    """Update security questions with 2FA verification"""
    if current_user.user_type != 'elderly':
        flash('Security questions are only available for elderly users.', 'warning')
        return redirect(url_for('main.profile'))
    
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
        flash('Security verification is only available for elderly users.', 'warning')
        return redirect(url_for('main.profile'))
    
    # Get available security questions for verification
    questions = []
    if current_user.security_q1 and current_user.security_a1:
        questions.append((current_user.security_q1, current_user.security_a1, 'security_q1'))
    if current_user.security_q2 and current_user.security_a2:
        questions.append((current_user.security_q2, current_user.security_a2, 'security_q2'))
    if current_user.security_q3 and current_user.security_a3:
        questions.append((current_user.security_q3, current_user.security_a3, 'security_q3'))
    
    if not questions:
        flash('No security questions are set up. You can update them directly.', 'info')
        session['security_verified'] = True
        return redirect(url_for('profile.security_questions'))
    
    # Select a random question for verification
    if 'verify_question' not in session:
        selected_question, correct_answer, question_key = random.choice(questions)
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
        user_answer = form.security_answer.data.lower().strip() if form.security_answer.data else ''
        correct_answer = session.get('verify_answer', '').lower().strip() if session.get('verify_answer') else ''
        attempts = session.get('verify_attempts', 0) + 1
        session['verify_attempts'] = attempts
        
        if user_answer == correct_answer:
            # Verification successful
            session['security_verified'] = True
            # Clear verification session data
            session.pop('verify_question', None)
            session.pop('verify_answer', None)
            session.pop('verify_attempts', None)
            
            flash('Identity verified successfully! You can now update your security questions.', 'success')
            return redirect(url_for('profile.security_questions'))
        else:
            if attempts >= 3:
                # Too many failed attempts - clear session and redirect
                session.pop('verify_question', None)
                session.pop('verify_answer', None)
                session.pop('verify_attempts', None)
                flash('Too many incorrect attempts. Please try again later or contact support.', 'danger')
                return redirect(url_for('profile.settings'))
            else:
                remaining = 3 - attempts
                flash(f'Incorrect answer. You have {remaining} attempt(s) remaining.', 'danger')
    
    return render_template('profile/verify_security.html', form=form, question=question_text, 
                         attempts=session.get('verify_attempts', 0))

@profile_bp.route('/delete-picture', methods=['POST'])
@login_required
def delete_picture():
    """Delete profile picture"""
    if current_user.user_type != 'elderly':
        flash('Profile management is only available for elderly users.', 'warning')
        return redirect(url_for('main.profile'))
    
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
def dashboard():
    """Organizer dashboard with event management"""
    if current_user.user_type != 'organizer':
        flash('Access denied. Organizer dashboard is only for event organizers.', 'danger')
        return redirect(url_for('main.index'))
    
    # Get organizer's events with different statuses
    pending_events = Event.query.filter_by(organizer_id=current_user.id, status='pending').order_by(Event.created_at.desc()).all()
    approved_events = Event.query.filter_by(organizer_id=current_user.id, status='approved').order_by(Event.date).all()
    rejected_events = Event.query.filter_by(organizer_id=current_user.id, status='rejected').order_by(Event.created_at.desc()).all()
    
    # Get statistics
    total_events = Event.query.filter_by(organizer_id=current_user.id).count()
    total_participants = db.session.query(db.func.count(EventRSVP.id)).join(Event).filter(Event.organizer_id == current_user.id, Event.status == 'approved').scalar() or 0
    total_volunteers = db.session.query(db.func.count(VolunteerApplication.id)).join(Event).filter(Event.organizer_id == current_user.id, VolunteerApplication.status == 'approved').scalar() or 0
    
    return render_template('organizer/dashboard.html', 
                         pending_events=pending_events,
                         approved_events=approved_events,
                         rejected_events=rejected_events,
                         total_events=total_events,
                         total_participants=total_participants,
                         total_volunteers=total_volunteers)

@organizer_bp.route('/create-event', methods=['GET', 'POST'])
@login_required
def create_event():
    """Create a new event"""
    if current_user.user_type != 'organizer':
        flash('Access denied. Only organizers can create events.', 'danger')
        return redirect(url_for('main.index'))
    
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
        flash('Event created successfully! It will be reviewed and approved before being visible to participants.', 'success')
        return redirect(url_for('organizer.dashboard'))
    
    return render_template('organizer/create_event.html', form=form)

@organizer_bp.route('/event/<int:event_id>')
@login_required
def event_detail(event_id):
    """View detailed event information and manage participants/volunteers"""
    if current_user.user_type != 'organizer':
        flash('Access denied. Only organizers can view event details.', 'danger')
        return redirect(url_for('main.index'))
    
    event = Event.query.get_or_404(event_id)
    
    # Ensure the organizer owns this event
    if event.organizer_id != current_user.id:
        flash('Access denied. You can only view your own events.', 'danger')
        return redirect(url_for('organizer.dashboard'))
    
    # Get participants and volunteers
    rsvps = EventRSVP.query.filter_by(event_id=event_id).all()
    participants = [rsvp.user for rsvp in rsvps]
    
    volunteer_apps = VolunteerApplication.query.filter_by(event_id=event_id).all()
    
    return render_template('organizer/event_detail.html', 
                         event=event, 
                         participants=participants,
                         volunteer_applications=volunteer_apps)

@organizer_bp.route('/volunteer/<int:app_id>/approve', methods=['POST'])
@login_required
def approve_volunteer(app_id):
    """Approve a volunteer application"""
    if current_user.user_type != 'organizer':
        flash('Access denied. Only organizers can manage volunteers.', 'danger')
        return redirect(url_for('main.index'))
    
    app = VolunteerApplication.query.get_or_404(app_id)
    
    # Verify organizer owns the event
    if app.event.organizer_id != current_user.id:
        flash('Access denied. You can only manage volunteers for your own events.', 'danger')
        return redirect(url_for('organizer.dashboard'))
    
    app.status = 'approved'
    db.session.commit()
    flash(f'Volunteer application from {app.volunteer.get_full_name()} has been approved!', 'success')
    
    return redirect(url_for('organizer.event_detail', event_id=app.event_id))

@organizer_bp.route('/volunteer/<int:app_id>/reject', methods=['POST'])
@login_required
def reject_volunteer(app_id):
    """Reject a volunteer application"""
    if current_user.user_type != 'organizer':
        flash('Access denied. Only organizers can manage volunteers.', 'danger')
        return redirect(url_for('main.index'))
    
    app = VolunteerApplication.query.get_or_404(app_id)
    
    # Verify organizer owns the event
    if app.event.organizer_id != current_user.id:
        flash('Access denied. You can only manage volunteers for your own events.', 'danger')
        return redirect(url_for('organizer.dashboard'))
    
    app.status = 'rejected'
    db.session.commit()
    flash(f'Volunteer application from {app.volunteer.get_full_name()} has been rejected.', 'info')
    
    return redirect(url_for('organizer.event_detail', event_id=app.event_id))

@organizer_bp.route('/event/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    """Edit an existing event"""
    if current_user.user_type != 'organizer':
        flash('Access denied. Only organizers can edit events.', 'danger')
        return redirect(url_for('main.index'))
    
    event = Event.query.get_or_404(event_id)
    
    # Ensure the organizer owns this event
    if event.organizer_id != current_user.id:
        flash('Access denied. You can only edit your own events.', 'danger')
        return redirect(url_for('organizer.dashboard'))
    
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
def delete_event(event_id):
    """Delete an event"""
    if current_user.user_type != 'organizer':
        flash('Access denied. Only organizers can delete events.', 'danger')
        return redirect(url_for('main.index'))
    
    event = Event.query.get_or_404(event_id)
    
    # Ensure the organizer owns this event
    if event.organizer_id != current_user.id:
        flash('Access denied. You can only delete your own events.', 'danger')
        return redirect(url_for('organizer.dashboard'))
    
    # Delete related records first
    EventRSVP.query.filter_by(event_id=event_id).delete()
    VolunteerApplication.query.filter_by(event_id=event_id).delete()
    
    db.session.delete(event)
    db.session.commit()
    
    flash('Event deleted successfully!', 'success')
    return redirect(url_for('organizer.dashboard'))
