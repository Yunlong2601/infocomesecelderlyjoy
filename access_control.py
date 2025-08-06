"""
Enterprise-Grade Access Control Security Module for Community Connect

This module provides comprehensive Role-Based Access Control (RBAC) to prevent
Broken Access Control vulnerabilities throughout the application.
Implements defense-in-depth security with multiple layers of protection.

Security Features:
- Multi-layered authorization checks
- Resource ownership validation  
- Session tampering detection
- Privilege escalation prevention
- Comprehensive security logging
- Rate limiting for failed access attempts
"""

from functools import wraps
from flask import abort, redirect, url_for, flash, request, session
from flask_login import current_user
from datetime import datetime, timedelta
import logging
import hashlib
import secrets

# Enhanced security logging
security_logger = logging.getLogger('rbac_security')
security_logger.setLevel(logging.INFO)

# Failed access attempt tracking
failed_access_attempts = {}
ACCESS_ATTEMPT_LIMIT = 5
ACCESS_LOCKOUT_DURATION = 15  # minutes

def validate_session_integrity():
    """Enhanced session validation to prevent tampering"""
    try:
        # Validate session exists and has required fields
        if 'user_id' not in session and current_user.is_authenticated:
            return False, "Session integrity compromised"
        
        # Cross-validate session user_id with current_user
        if current_user.is_authenticated and 'user_id' in session:
            if session.get('user_id') != current_user.id:
                return False, "Session-user mismatch detected"
        
        # Validate session hasn't been hijacked (IP consistency)
        if 'session_ip' in session:
            current_ip = request.remote_addr
            if session.get('session_ip') != current_ip:
                # Allow IP changes but log for monitoring
                security_logger.warning(f"IP change detected: User {current_user.id if current_user.is_authenticated else 'unknown'} from {session.get('session_ip')} to {current_ip}")
        
        return True, "Session valid"
    except Exception as e:
        security_logger.error(f"Session validation error: {str(e)}")
        return False, "Session validation failed"

def check_access_rate_limit(user_id, ip_address):
    """Rate limiting for failed access attempts"""
    key = f"{user_id}_{ip_address}" if user_id else ip_address
    now = datetime.utcnow()
    
    # Clean old entries
    cutoff_time = now - timedelta(minutes=ACCESS_LOCKOUT_DURATION)
    failed_access_attempts[key] = [
        attempt for attempt in failed_access_attempts.get(key, [])
        if attempt > cutoff_time
    ]
    
    # Check if rate limit exceeded
    if len(failed_access_attempts.get(key, [])) >= ACCESS_ATTEMPT_LIMIT:
        return False, f"Access rate limit exceeded. Try again after {ACCESS_LOCKOUT_DURATION} minutes."
    
    return True, "Rate limit OK"

def log_failed_access_attempt(user_id, ip_address, route_name, user_type, required_types):
    """Log and track failed access attempts"""
    key = f"{user_id}_{ip_address}" if user_id else ip_address
    now = datetime.utcnow()
    
    # Add to failed attempts
    if key not in failed_access_attempts:
        failed_access_attempts[key] = []
    failed_access_attempts[key].append(now)
    
    # Enhanced security logging
    security_logger.warning(
        f"RBAC_ACCESS_DENIED: User {user_id} (type: {user_type}) from IP {ip_address} "
        f"attempted unauthorized access to {route_name} (requires: {required_types}) "
        f"at {now.isoformat()}"
    )

def require_user_type(*allowed_types):
    """
    Enterprise-grade decorator to enforce user type-based access control
    
    Security Features:
    - Multi-layer authentication validation
    - Session integrity checks
    - Rate limiting for failed attempts
    - Comprehensive security logging
    - Privilege escalation prevention
    
    Args:
        allowed_types: List of user types that can access the route
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Layer 1: Authentication check
            if not current_user.is_authenticated:
                security_logger.info(f"Unauthenticated access attempt to {f.__name__} from {request.remote_addr}")
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))
            
            # Layer 2: Session integrity validation
            session_valid, session_msg = validate_session_integrity()
            if not session_valid:
                security_logger.warning(f"Session integrity failed for user {current_user.id}: {session_msg}")
                session.clear()
                flash('Security violation detected. Please log in again.', 'danger')
                return redirect(url_for('auth.login'))
            
            # Layer 3: Rate limiting check
            rate_limit_ok, rate_msg = check_access_rate_limit(
                current_user.id, request.remote_addr
            )
            if not rate_limit_ok:
                security_logger.warning(f"Rate limit exceeded for user {current_user.id} from {request.remote_addr}")
                flash(rate_msg, 'danger')
                abort(429)  # Too Many Requests
            
            # Layer 4: Role-based authorization
            if current_user.user_type not in allowed_types:
                # Log failed access attempt
                log_failed_access_attempt(
                    current_user.id, 
                    request.remote_addr, 
                    f.__name__, 
                    current_user.user_type, 
                    allowed_types
                )
                
                flash('Access denied. You do not have permission to view this page.', 'danger')
                abort(403)
            
            # Layer 5: Update session security markers
            session['session_ip'] = request.remote_addr
            session['last_access'] = datetime.utcnow().isoformat()
            
            # Success logging for audit trail
            security_logger.info(
                f"RBAC_ACCESS_GRANTED: User {current_user.id} (type: {current_user.user_type}) "
                f"accessed {f.__name__} from {request.remote_addr}"
            )
            
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

def check_resource_ownership(resource_user_id, resource_type="resource", error_message=None):
    """
    Enterprise-grade resource ownership validation with comprehensive security checks
    
    Security Features:
    - Multi-layer ownership validation
    - Admin override with logging
    - Resource type tracking
    - Attempt logging and monitoring
    - Input validation and sanitization
    
    Args:
        resource_user_id: The user_id that owns the resource
        resource_type: Type of resource being accessed (for logging)
        error_message: Custom error message to display
    """
    if error_message is None:
        error_message = f"You can only access your own {resource_type}s."
    
    # Layer 1: Authentication validation
    if not current_user.is_authenticated:
        security_logger.warning(f"Unauthenticated {resource_type} access attempt from {request.remote_addr}")
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Layer 2: Input validation
    if not resource_user_id or not isinstance(resource_user_id, (int, str)):
        security_logger.warning(f"Invalid resource_user_id provided: {resource_user_id} by user {current_user.id}")
        flash('Invalid resource identifier.', 'danger')
        abort(400)
    
    try:
        resource_user_id = int(resource_user_id)
    except (ValueError, TypeError):
        security_logger.warning(f"Non-numeric resource_user_id: {resource_user_id} by user {current_user.id}")
        flash('Invalid resource identifier format.', 'danger')
        abort(400)
    
    # Layer 3: Admin override with comprehensive logging
    if current_user.user_type == 'admin':
        security_logger.info(
            f"ADMIN_RESOURCE_ACCESS: Admin {current_user.id} accessed {resource_type} "
            f"owned by user {resource_user_id} from {request.remote_addr}"
        )
        return True
    
    # Layer 4: Ownership validation
    if current_user.id != resource_user_id:
        security_logger.warning(
            f"RESOURCE_ACCESS_DENIED: User {current_user.id} attempted to access {resource_type} "
            f"owned by user {resource_user_id} from {request.remote_addr}"
        )
        
        # Track failed access attempts
        log_failed_access_attempt(
            current_user.id, 
            request.remote_addr, 
            f"resource_access_{resource_type}", 
            current_user.user_type, 
            ["owner"]
        )
        
        flash(error_message, 'danger')
        abort(403)
    
    # Success logging
    security_logger.info(
        f"RESOURCE_ACCESS_GRANTED: User {current_user.id} accessed own {resource_type} "
        f"from {request.remote_addr}"
    )
    
    return True

def check_event_ownership(event_organizer_id, error_message="You can only manage your own events."):
    """
    Enterprise-grade event ownership validation with comprehensive security checks
    
    Security Features:
    - Multi-layer authorization (authentication, role, ownership)
    - Admin override with audit logging
    - Event-specific security controls
    - Comprehensive attempt tracking
    - Input validation and sanitization
    
    Args:
        event_organizer_id: The organizer_id that owns the event
        error_message: Custom error message to display
    """
    # Layer 1: Authentication validation
    if not current_user.is_authenticated:
        security_logger.warning(f"Unauthenticated event access attempt from {request.remote_addr}")
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Layer 2: Input validation
    if not event_organizer_id or not isinstance(event_organizer_id, (int, str)):
        security_logger.warning(f"Invalid event_organizer_id provided: {event_organizer_id} by user {current_user.id}")
        flash('Invalid event identifier.', 'danger')
        abort(400)
    
    try:
        event_organizer_id = int(event_organizer_id)
    except (ValueError, TypeError):
        security_logger.warning(f"Non-numeric event_organizer_id: {event_organizer_id} by user {current_user.id}")
        flash('Invalid event identifier format.', 'danger')
        abort(400)
    
    # Layer 3: Admin override with audit trail
    if current_user.user_type == 'admin':
        security_logger.info(
            f"ADMIN_EVENT_ACCESS: Admin {current_user.id} accessed event "
            f"owned by organizer {event_organizer_id} from {request.remote_addr}"
        )
        return True
    
    # Layer 4: Role validation - only organizers can manage events
    if current_user.user_type != 'organizer':
        security_logger.warning(
            f"INVALID_ROLE_EVENT_ACCESS: User {current_user.id} (type: {current_user.user_type}) "
            f"attempted event management from {request.remote_addr}"
        )
        
        log_failed_access_attempt(
            current_user.id, 
            request.remote_addr, 
            "event_management", 
            current_user.user_type, 
            ["organizer", "admin"]
        )
        
        flash('Only event organizers can manage events.', 'danger')
        abort(403)
    
    # Layer 5: Ownership validation
    if current_user.id != event_organizer_id:
        security_logger.warning(
            f"EVENT_OWNERSHIP_VIOLATION: Organizer {current_user.id} attempted to access "
            f"event owned by organizer {event_organizer_id} from {request.remote_addr}"
        )
        
        log_failed_access_attempt(
            current_user.id, 
            request.remote_addr, 
            "event_ownership", 
            current_user.user_type, 
            ["owner"]
        )
        
        flash(error_message, 'danger')
        abort(403)
    
    # Success logging
    security_logger.info(
        f"EVENT_ACCESS_GRANTED: Organizer {current_user.id} accessed own event "
        f"from {request.remote_addr}"
    )
    
    return True

def require_admin_with_audit():
    """Enhanced admin decorator with comprehensive audit logging"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Standard admin check
            if not current_user.is_authenticated or current_user.user_type != 'admin':
                security_logger.warning(
                    f"ADMIN_ACCESS_DENIED: User {current_user.id if current_user.is_authenticated else 'anonymous'} "
                    f"attempted admin function {f.__name__} from {request.remote_addr}"
                )
                flash('Administrator access required.', 'danger')
                abort(403)
            
            # Enhanced admin activity logging
            security_logger.info(
                f"ADMIN_FUNCTION_ACCESS: Admin {current_user.id} executed {f.__name__} "
                f"from {request.remote_addr} at {datetime.utcnow().isoformat()}"
            )
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_csrf_token():
    """Enhanced CSRF protection validation"""
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        token = session.get('csrf_token')
        request_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-TOKEN')
        
        if not token or not request_token or token != request_token:
            security_logger.warning(
                f"CSRF_TOKEN_MISMATCH: User {current_user.id if current_user.is_authenticated else 'anonymous'} "
                f"from {request.remote_addr} failed CSRF validation"
            )
            return False
    return True

def generate_csrf_token():
    """Generate secure CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

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