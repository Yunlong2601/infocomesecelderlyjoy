import os
import json
import logging
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from flask import Flask
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from unified_security_system import initialize_security_system
from extensions import db, login_manager, mail

# Configure enhanced security logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

# Create the app
app = Flask(__name__)

# Enhanced security configuration
app.secret_key = os.environ.get("SESSION_SECRET")
if not app.secret_key:
    raise ValueError("SESSION_SECRET environment variable must be set for security")

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Comprehensive security configuration
app.config.update(
    # Session security (Cryptographic Failures protection)
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    
    # CSRF protection (Security Misconfiguration)
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=None,
    
    # File upload security (Insecure Design)
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max
    
    # Database security (SQL Injection)
    SQLALCHEMY_ECHO=False,  # Never log SQL in production
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

# Configure the database with enhanced security
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///community_connect.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "echo": False,  # Prevent SQL injection via logs
    "pool_timeout": 20,
    "max_overflow": 0,
}

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'samplebookshopnyp@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('GMAIL_APP_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'samplebookshopnyp@gmail.com'

# Initialize extensions with app
db.init_app(app)
login_manager.init_app(app)
mail.init_app(app)
login_manager.login_view = 'auth.login'  # type: ignore
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = "strong"  # Enhanced session protection

# Initialize unified security system
app = initialize_security_system(app)

# Session management middleware
@app.before_request
def before_request():
    """Session validation middleware"""
    from flask import session, request, redirect, url_for, flash
    from flask_login import current_user
    
    # Skip session validation for static files and auth routes
    if request.endpoint and (
        request.endpoint.startswith('static') or 
        request.endpoint.startswith('auth') or
        request.endpoint == 'main.index'
    ):
        return
    
    # Only validate custom session data if user is authenticated via Flask-Login
    if current_user.is_authenticated and 'user_id' in session:
        # Basic session validation without interfering with Flask-Login
        if session.get('user_id') != current_user.id:
            # Session mismatch - clear custom session data but don't force logout
            session.pop('user_id', None)

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Add custom template filters
@app.template_filter('from_json')
def from_json_filter(value):
    """Convert JSON string to Python object"""
    if not value:
        return []
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []

# Security headers configuration (Security Misconfiguration)
@app.after_request
def set_security_headers(response):
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content type sniffing protection
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # HTTPS enforcement (in production)
    if app.config.get('ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Enhanced Content Security Policy with HSTS
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.replit.com https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.replit.com https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdn.replit.com https://fonts.googleapis.com https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    
    # HSTS Header for HTTPS enforcement
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

# Import and register routes after app initialization - delayed import to avoid circular dependency
def register_blueprints(app):
    from routes import main_bp, auth_bp, events_bp, profile_bp, organizer_bp, volunteer_bp, admin_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(events_bp, url_prefix='/events')
    app.register_blueprint(profile_bp, url_prefix='/profile')
    app.register_blueprint(organizer_bp, url_prefix='/organizer')
    app.register_blueprint(volunteer_bp, url_prefix='/volunteer')
    app.register_blueprint(admin_bp, url_prefix='/admin')

# Register blueprints first
register_blueprints(app)

# Then create tables within app context
with app.app_context():
    # Import models to ensure tables are created
    import models  # noqa: F401
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
