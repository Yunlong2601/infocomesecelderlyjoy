from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, TextAreaField, SelectField, DateTimeField, IntegerField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, NumberRange, Regexp
from wtforms.widgets import TextArea, CheckboxInput, ListWidget
from datetime import datetime

class LoginForm(FlaskForm):
    nric = StringField('NRIC', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg', 'placeholder': 'e.g., P1234567J'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    submit = SubmitField('Sign In', render_kw={'class': 'btn btn-primary btn-lg w-100'})

class MultiCheckboxField(SelectMultipleField):
    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()

class RegistrationForm(FlaskForm):
    user_type = SelectField('I am a:', choices=[
        ('elderly', 'Elderly Community Member'),
        ('organizer', 'Event Organizer'),
        ('volunteer', 'Volunteer Helper')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    
    # Elderly-specific fields
    nric = StringField('NRIC', validators=[
        DataRequired(),
        Regexp(r'^[STFG]\d{7}[A-Z]$', message='Please enter valid NRIC format (e.g., S1234567A)')
    ], render_kw={'class': 'form-control form-control-lg', 'placeholder': 'e.g., S1234567A'})
    
    full_name = StringField('Full Name', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    
    language_preference = SelectField('Language Preference', choices=[
        ('english', 'English'),
        ('mandarin', 'Mandarin'),
        ('malay', 'Malay'),
        ('tamil', 'Tamil'),
        ('hokkien', 'Hokkien'),
        ('cantonese', 'Cantonese')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    
    event_interests = MultiCheckboxField('Event Interests (Optional)', choices=[
        ('social', 'Social Gatherings (Tea sessions, community dinners)'),
        ('recreational', 'Recreational Activities (Exercise, games, outings)'),
        ('educational', 'Educational Events (Health talks, skill workshops)'),
        ('cultural', 'Cultural Events (Festivals, performances)'),
        ('health', 'Health & Wellness (Medical screenings, fitness classes)')
    ], validators=[Optional()])
    
    # Security Questions for 2FA
    security_q1 = SelectField('Security Question 1', choices=[
        ('', 'Choose a question...'),
        ('birthplace', 'What is your place of birth?'),
        ('school', 'What was the name of your primary school?'),
        ('mother_maiden', 'What is your mother\'s maiden name?'),
        ('first_pet', 'What was the name of your first pet?')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    
    security_a1 = StringField('Answer', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    
    security_q2 = SelectField('Security Question 2', choices=[
        ('', 'Choose a question...'),
        ('childhood_friend', 'Who was your best friend in childhood?'),
        ('first_job', 'What was your first job?'),
        ('favorite_food', 'What is your favorite food?'),
        ('childhood_street', 'What street did you grow up on?')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    
    security_a2 = StringField('Answer', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    
    security_q3 = SelectField('Security Question 3', choices=[
        ('', 'Choose a question...'),
        ('spouse_birthplace', 'Where was your spouse born?'),
        ('favorite_color', 'What is your favorite color?'),
        ('first_car', 'What was your first car model?'),
        ('wedding_venue', 'Where did you get married?')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    
    security_a3 = StringField('Answer', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    
    # Organizer/Volunteer fields
    first_name = StringField('First Name', validators=[Optional()], render_kw={'class': 'form-control form-control-lg'})
    last_name = StringField('Last Name', validators=[Optional()], render_kw={'class': 'form-control form-control-lg'})
    email = StringField('Email', validators=[Optional(), Email()], render_kw={'class': 'form-control form-control-lg'})
    phone = StringField('Phone Number', validators=[Optional()], render_kw={'class': 'form-control form-control-lg'})
    
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)], render_kw={'class': 'form-control form-control-lg'})
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={'class': 'form-control form-control-lg'})
    submit = SubmitField('Register', render_kw={'class': 'btn btn-primary btn-lg w-100'})

class EventForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired(), Length(max=100)], render_kw={'class': 'form-control form-control-lg'})
    description = TextAreaField('Description', validators=[Optional()], render_kw={'class': 'form-control', 'rows': 4})
    category = SelectField('Category', choices=[
        ('social', 'Social Gathering'),
        ('recreational', 'Recreational Activity'),
        ('educational', 'Educational/Learning')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    date = DateTimeField('Date and Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M', render_kw={'class': 'form-control form-control-lg', 'type': 'datetime-local'})
    duration_hours = IntegerField('Duration (hours)', validators=[DataRequired(), NumberRange(min=1, max=12)], default=2, render_kw={'class': 'form-control form-control-lg'})
    location = StringField('Location', validators=[DataRequired(), Length(max=200)], render_kw={'class': 'form-control form-control-lg'})
    max_participants = IntegerField('Maximum Participants', validators=[Optional(), NumberRange(min=1)], render_kw={'class': 'form-control form-control-lg'})
    volunteers_needed = IntegerField('Volunteers Needed', validators=[Optional(), NumberRange(min=0)], default=0, render_kw={'class': 'form-control form-control-lg'})
    submit = SubmitField('Create Event', render_kw={'class': 'btn btn-success btn-lg'})

class VolunteerApplicationForm(FlaskForm):
    message = TextAreaField('Why would you like to volunteer for this event?', validators=[Optional()], render_kw={'class': 'form-control', 'rows': 3})
    submit = SubmitField('Apply to Volunteer', render_kw={'class': 'btn btn-primary btn-lg'})

class TwoFactorForm(FlaskForm):
    security_answer = StringField('Security Answer', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    submit = SubmitField('Verify', render_kw={'class': 'btn btn-primary btn-lg w-100'})

class ElderlyProfileForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    
    language_preference = SelectField('Language Preference', choices=[
        ('english', 'English'),
        ('mandarin', 'Mandarin'),
        ('malay', 'Malay'),
        ('tamil', 'Tamil'),
        ('hokkien', 'Hokkien'),
        ('cantonese', 'Cantonese')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    
    event_interests = MultiCheckboxField('Event Interests', choices=[
        ('social', 'Social Gatherings (Tea sessions, community dinners)'),
        ('recreational', 'Recreational Activities (Exercise, games, outings)'),
        ('educational', 'Educational Events (Health talks, skill workshops)'),
        ('cultural', 'Cultural Events (Festivals, performances)'),
        ('health', 'Health & Wellness (Medical screenings, fitness classes)')
    ], validators=[Optional()])
    
    profile_picture = FileField('Profile Picture', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Only image files are allowed!')
    ], render_kw={'class': 'form-control form-control-lg'})
    
    submit = SubmitField('Update Profile', render_kw={'class': 'btn btn-success btn-lg'})

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long')
    ], render_kw={'class': 'form-control form-control-lg'})
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ], render_kw={'class': 'form-control form-control-lg'})
    submit = SubmitField('Change Password', render_kw={'class': 'btn btn-warning btn-lg'})

class SecurityQuestionsForm(FlaskForm):
    security_q1 = SelectField('Security Question 1', choices=[
        ('', 'Choose a question...'),
        ('birthplace', 'What is your place of birth?'),
        ('school', 'What was the name of your primary school?'),
        ('mother_maiden', 'What is your mother\'s maiden name?'),
        ('first_pet', 'What was the name of your first pet?')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    
    security_a1 = StringField('Answer', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    
    security_q2 = SelectField('Security Question 2', choices=[
        ('', 'Choose a question...'),
        ('childhood_friend', 'Who was your best friend in childhood?'),
        ('first_job', 'What was your first job?'),
        ('favorite_food', 'What is your favorite food?'),
        ('childhood_street', 'What street did you grow up on?')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    
    security_a2 = StringField('Answer', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    
    security_q3 = SelectField('Security Question 3', choices=[
        ('', 'Choose a question...'),
        ('spouse_birthplace', 'Where was your spouse born?'),
        ('favorite_color', 'What is your favorite color?'),
        ('first_car', 'What was your first car model?'),
        ('wedding_venue', 'Where did you get married?')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
    
    security_a3 = StringField('Answer', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    
    password_confirm = PasswordField('Enter Your Password to Confirm', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    
    submit = SubmitField('Update Security Questions', render_kw={'class': 'btn btn-info btn-lg'})
