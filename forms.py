from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, DateTimeField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, NumberRange
from wtforms.widgets import TextArea
from datetime import datetime

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    submit = SubmitField('Sign In', render_kw={'class': 'btn btn-primary btn-lg w-100'})

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)], render_kw={'class': 'form-control form-control-lg'})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'class': 'form-control form-control-lg'})
    first_name = StringField('First Name', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    last_name = StringField('Last Name', validators=[DataRequired()], render_kw={'class': 'form-control form-control-lg'})
    phone = StringField('Phone Number', validators=[Optional()], render_kw={'class': 'form-control form-control-lg'})
    user_type = SelectField('I am a:', choices=[
        ('elderly', 'Community Member (Looking for Events)'),
        ('organizer', 'Event Organizer'),
        ('volunteer', 'Volunteer Helper')
    ], validators=[DataRequired()], render_kw={'class': 'form-select form-select-lg'})
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
