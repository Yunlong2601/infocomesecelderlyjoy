"""
Access Control Security Module for Community Connect

This module provides comprehensive access control functions to prevent
Broken Access Control vulnerabilities throughout the application.
"""

from functools import wraps
from flask import abort, redirect, url_for, flash
from flask_login import current_user
import logging

def require_user_type(*allowed_types):
    """
    Decorator to enforce user type-based access control
    
    Args:
        allowed_types: List of user types that can access the route
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))
            
            if current_user.user_type not in allowed_types:
                logging.warning(f"Access denied: User {current_user.id} ({current_user.user_type}) tried to access {f.__name__} (requires {allowed_types})")
                flash('Access denied. You do not have permission to view this page.', 'danger')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_admin():
    """Decorator specifically for admin-only routes"""
    return require_user_type('admin')

def require_organizer():
    """Decorator specifically for organizer-only routes"""
    return require_user_type('organizer')

def require_volunteer():
    """Decorator specifically for volunteer-only routes"""
    return require_user_type('volunteer')

def require_elderly():
    """Decorator specifically for elderly user-only routes"""
    return require_user_type('elderly')

def require_organizer_or_admin():
    """Decorator for routes accessible by organizers or admins"""
    return require_user_type('organizer', 'admin')

def require_volunteer_or_admin():
    """Decorator for routes accessible by volunteers or admins"""
    return require_user_type('volunteer', 'admin')

def check_resource_ownership(resource_user_id, error_message="You can only access your own resources."):
    """
    Check if current user owns the resource
    
    Args:
        resource_user_id: The user_id that owns the resource
        error_message: Custom error message to display
    """
    if not current_user.is_authenticated:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Admin can access all resources
    if current_user.user_type == 'admin':
        return True
    
    # Check if user owns the resource
    if current_user.id != resource_user_id:
        logging.warning(f"Resource access denied: User {current_user.id} tried to access resource owned by {resource_user_id}")
        flash(error_message, 'danger')
        abort(403)
    
    return True

def check_event_ownership(event_organizer_id, error_message="You can only manage your own events."):
    """
    Check if current user owns the event (for organizers)
    
    Args:
        event_organizer_id: The organizer_id that owns the event
        error_message: Custom error message to display
    """
    if not current_user.is_authenticated:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Admin can access all events
    if current_user.user_type == 'admin':
        return True
    
    # Only organizers can manage events
    if current_user.user_type != 'organizer':
        flash('Only event organizers can manage events.', 'danger')
        abort(403)
    
    # Check if organizer owns the event
    if current_user.id != event_organizer_id:
        logging.warning(f"Event access denied: Organizer {current_user.id} tried to access event owned by {event_organizer_id}")
        flash(error_message, 'danger')
        abort(403)
    
    return True

def check_application_ownership(application_volunteer_id, error_message="You can only access your own applications."):
    """
    Check if current user owns the volunteer application
    
    Args:
        application_volunteer_id: The volunteer_id that owns the application
        error_message: Custom error message to display
    """
    if not current_user.is_authenticated:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Admin can access all applications
    if current_user.user_type == 'admin':
        return True
    
    # Check if user owns the application
    if current_user.id != application_volunteer_id:
        logging.warning(f"Application access denied: User {current_user.id} tried to access application owned by {application_volunteer_id}")
        flash(error_message, 'danger')
        abort(403)
    
    return True

def sanitize_user_input(input_string, max_length=255):
    """
    Sanitize user input to prevent injection attacks
    
    Args:
        input_string: The input string to sanitize
        max_length: Maximum allowed length
    """
    if not input_string:
        return ""
    
    # Strip whitespace and limit length
    sanitized = str(input_string).strip()[:max_length]
    
    # Remove potentially dangerous characters for SQL injection prevention
    # Note: We're using SQLAlchemy with parameterized queries, but this adds extra protection
    dangerous_chars = ['<script', '</script', 'javascript:', 'onclick=', 'onerror=']
    for char in dangerous_chars:
        sanitized = sanitized.replace(char.lower(), '').replace(char.upper(), '')
    
    return sanitized

def validate_file_upload(filename):
    """
    Validate uploaded file for security
    
    Args:
        filename: The filename to validate
        
    Returns:
        bool: True if file is safe to upload
    """
    if not filename:
        return False
    
    # Check file extension
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if file_ext not in allowed_extensions:
        return False
    
    # Check for dangerous filenames
    dangerous_names = ['..', '/', '\\', 'con', 'aux', 'nul', 'prn']
    filename_lower = filename.lower()
    
    for dangerous in dangerous_names:
        if dangerous in filename_lower:
            return False
    
    return True

def log_security_event(event_type, user_id=None, details=""):
    """
    Log security-related events for monitoring
    
    Args:
        event_type: Type of security event (e.g., 'access_denied', 'login_attempt')
        user_id: ID of the user involved
        details: Additional details about the event
    """
    user_info = f"User {user_id}" if user_id else "Anonymous"
    logging.warning(f"SECURITY EVENT [{event_type}]: {user_info} - {details}")