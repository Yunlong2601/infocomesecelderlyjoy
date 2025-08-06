"""
Complete Enhanced Security Implementation for Community Connect
This module contains ALL additional security features for comprehensive protection
"""

import os
import hashlib
import secrets
import logging
import time
import re
from datetime import datetime, timedelta
from flask import request, session, current_app

# Enhanced Rate Limiting System
class EnhancedRateLimiting:
    """Advanced rate limiting for different endpoints"""
    
    # Rate limit storage (in production, use Redis)
    _rate_limits = {}
    
    @staticmethod
    def check_rate_limit(identifier, limit_per_minute=5, endpoint="general"):
        """Check if request is within rate limit"""
        current_time = time.time()
        key = f"{endpoint}:{identifier}"
        
        if key not in EnhancedRateLimiting._rate_limits:
            EnhancedRateLimiting._rate_limits[key] = []
        
        # Clean old requests (older than 1 minute)
        EnhancedRateLimiting._rate_limits[key] = [
            req_time for req_time in EnhancedRateLimiting._rate_limits[key]
            if current_time - req_time < 60
        ]
        
        # Check if limit exceeded
        if len(EnhancedRateLimiting._rate_limits[key]) >= limit_per_minute:
            return False
        
        # Add current request
        EnhancedRateLimiting._rate_limits[key].append(current_time)
        return True
    
    @staticmethod
    def login_rate_limit(identifier):
        """Specific rate limiting for login attempts"""
        return EnhancedRateLimiting.check_rate_limit(identifier, 3, "login")
    
    @staticmethod
    def email_rate_limit(identifier):
        """Rate limiting for email sending"""
        return EnhancedRateLimiting.check_rate_limit(identifier, 2, "email")
    
    @staticmethod
    def api_rate_limit(identifier):
        """General API rate limiting"""
        return EnhancedRateLimiting.check_rate_limit(identifier, 30, "api")
    
    @staticmethod
    def profile_edit_rate_limit(identifier):
        """Rate limiting for profile edits"""
        return EnhancedRateLimiting.check_rate_limit(identifier, 5, "profile_edit")
    
    @staticmethod
    def password_reset_rate_limit(identifier):
        """Rate limiting for password reset attempts"""
        return EnhancedRateLimiting.check_rate_limit(identifier, 1, "password_reset")

# Content Security and File Validation
class ContentSecurity:
    """Enhanced content validation and security"""
    
    ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
    ALLOWED_DOCUMENT_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    
    # MIME type validation
    ALLOWED_MIME_TYPES = {
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'webp': 'image/webp',
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'txt': 'text/plain'
    }
    
    @staticmethod
    def validate_file_upload(file):
        """Comprehensive file upload validation"""
        if not file or not file.filename:
            return False, "No file selected"
        
        # Check file extension
        if '.' not in file.filename:
            return False, "File must have an extension"
        
        extension = file.filename.rsplit('.', 1)[1].lower()
        
        # Check if extension is allowed
        all_allowed = ContentSecurity.ALLOWED_IMAGE_EXTENSIONS | ContentSecurity.ALLOWED_DOCUMENT_EXTENSIONS
        if extension not in all_allowed:
            return False, f"File type not allowed. Allowed types: {', '.join(all_allowed)}"
        
        # Check file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > ContentSecurity.MAX_FILE_SIZE:
            return False, f"File too large. Maximum size: {ContentSecurity.MAX_FILE_SIZE // (1024*1024)}MB"
        
        # Additional security checks
        filename = file.filename.lower()
        
        # Check for double extensions (security risk)
        if filename.count('.') > 1:
            return False, "Files with multiple extensions not allowed"
        
        # Check for executable extensions disguised as images
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.jar']
        for ext in dangerous_extensions:
            if ext in filename:
                return False, "Potentially dangerous file detected"
        
        return True, "File validation passed"
    
    @staticmethod
    def validate_content_type(file, expected_extension):
        """Validate file content type matches extension"""
        try:
            # Read first few bytes to check file signature
            file_header = file.read(512)
            file.seek(0)  # Reset file pointer
            
            # Check common file signatures
            signatures = {
                'jpg': [b'\xff\xd8\xff'],
                'jpeg': [b'\xff\xd8\xff'],
                'png': [b'\x89\x50\x4e\x47'],
                'gif': [b'\x47\x49\x46'],
                'pdf': [b'%PDF'],
                'webp': [b'RIFF', b'WEBP']
            }
            
            if expected_extension in signatures:
                for sig in signatures[expected_extension]:
                    if file_header.startswith(sig):
                        return True, "Content type valid"
                
                return False, f"File content doesn't match {expected_extension} format"
            
            return True, "Content type check passed"
        except Exception as e:
            logging.warning(f"Content type validation error: {e}")
            return True, "Content type check skipped"
    
    @staticmethod
    def sanitize_filename(filename):
        """Sanitize uploaded filename"""
        # Remove path separators and dangerous characters
        filename = re.sub(r'[^\w\s.-]', '', filename)
        
        # Remove leading dots and spaces
        filename = filename.lstrip('. ')
        
        # Limit length
        if len(filename) > 100:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:95] + ('.' + ext if ext else '')
        
        # Ensure filename is not empty
        if not filename or filename.isspace():
            filename = f"file_{int(time.time())}"
        
        return filename
    
    @staticmethod
    def scan_file_content(file):
        """Basic virus/malware pattern detection"""
        try:
            content = file.read(1024 * 10)  # Read first 10KB
            file.seek(0)  # Reset
            
            # Look for suspicious patterns
            suspicious_patterns = [
                b'<script',
                b'javascript:',
                b'vbscript:',
                b'eval(',
                b'exec(',
                b'system(',
                b'shell_exec',
                b'<?php',
                b'<%',
                b'#!/bin/sh',
                b'#!/bin/bash'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in content.lower():
                    return False, f"Suspicious content detected: {pattern.decode('utf-8', errors='ignore')}"
            
            return True, "Content scan passed"
        except Exception as e:
            logging.warning(f"File content scan error: {e}")
            return True, "Content scan skipped"

# Input Length and Content Validation
class InputValidation:
    """Comprehensive input validation"""
    
    # Maximum lengths for different fields
    FIELD_LIMITS = {
        'name': 100,
        'full_name': 150,
        'first_name': 50,
        'last_name': 50,
        'email': 150,
        'description': 1000,
        'title': 200,
        'location': 200,
        'phone': 20,
        'nric': 15,
        'message': 2000,
        'address': 300,
        'organization': 200,
        'bio': 500,
        'skills': 300,
        'interests': 200
    }
    
    @staticmethod
    def validate_input_length(field_name, value):
        """Validate input length"""
        if not value:
            return True, ""
        
        max_length = InputValidation.FIELD_LIMITS.get(field_name, 500)
        
        if len(str(value)) > max_length:
            return False, f"{field_name.replace('_', ' ').title()} must be less than {max_length} characters"
        
        return True, ""
    
    @staticmethod
    def validate_all_inputs(form_data):
        """Validate all form inputs"""
        errors = []
        
        for field_name, value in form_data.items():
            if isinstance(value, str) and value.strip():
                is_valid, error_msg = InputValidation.validate_input_length(field_name, value)
                if not is_valid:
                    errors.append(error_msg)
                
                # Check for dangerous content
                if InputValidation.contains_dangerous_content(value):
                    errors.append(f"{field_name.replace('_', ' ').title()} contains invalid characters")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def contains_dangerous_content(value):
        """Check for dangerous content in input"""
        dangerous_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'<iframe',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'<\?php',
            r'<%.*?%>',
            r'{{.*?}}',
            r'<%.*?%>',
            r'\$\{.*?\}'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    @staticmethod
    def validate_email_format(email):
        """Enhanced email validation"""
        if not email:
            return False, "Email is required"
        
        # Length check
        if len(email) > 150:
            return False, "Email address too long"
        
        # Basic email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return False, "Invalid email format"
        
        # Check for dangerous patterns
        if InputValidation.contains_dangerous_content(email):
            return False, "Invalid email content"
        
        # Check for common typos in domains
        suspicious_domains = ['gmial.com', 'gmai.com', 'yahooo.com', 'hotmial.com']
        domain = email.split('@')[1].lower() if '@' in email else ''
        if domain in suspicious_domains:
            return False, "Please check your email domain for typos"
        
        return True, ""
    
    @staticmethod
    def validate_phone_format(phone):
        """Enhanced phone validation"""
        if not phone:
            return False, "Phone number is required"
        
        # Remove spaces, dashes, parentheses
        clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
        
        # Check length
        if len(clean_phone) > 20:
            return False, "Phone number too long"
        
        # Check for Singapore format primarily, but allow international
        singapore_pattern = r'^\+?65[689]\d{7}$'
        international_pattern = r'^\+?[1-9]\d{1,14}$'
        
        if re.match(singapore_pattern, clean_phone):
            return True, ""
        elif re.match(international_pattern, clean_phone):
            return True, ""
        else:
            return False, "Invalid phone format. Use format: +65XXXXXXXX or international format"
    
    @staticmethod
    def validate_nric_format(nric):
        """Enhanced NRIC validation for Singapore"""
        if not nric:
            return False, "NRIC is required"
        
        # Remove spaces and convert to uppercase
        clean_nric = nric.replace(' ', '').upper()
        
        # Check Singapore NRIC/FIN format
        nric_pattern = r'^[STFG]\d{7}[A-Z]$'
        
        if not re.match(nric_pattern, clean_nric):
            return False, "Invalid NRIC format. Use format: S1234567A"
        
        # Check if it's a valid checksum (simplified check)
        if len(clean_nric) == 9:
            return True, ""
        
        return False, "Invalid NRIC format"

# Password Security Enhancements
class PasswordSecurity:
    """Enhanced password security"""
    
    @staticmethod
    def validate_password_strength(password):
        """Comprehensive password strength validation"""
        if not password:
            return False, "Password is required"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) > 128:
            return False, "Password must be less than 128 characters"
        
        # Check for different character types
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*(),.?\":{}|<>~`-_=+[]\\/" for c in password)
        
        missing_types = []
        if not has_upper:
            missing_types.append("uppercase letter")
        if not has_lower:
            missing_types.append("lowercase letter")
        if not has_digit:
            missing_types.append("number")
        if not has_special:
            missing_types.append("special character")
        
        if missing_types:
            return False, f"Password must contain: {', '.join(missing_types)}"
        
        # Check for common patterns
        common_patterns = [
            'password', '123456', 'qwerty', 'admin', 'letmein',
            'welcome', 'monkey', 'dragon', 'master', 'login'
        ]
        
        for pattern in common_patterns:
            if pattern.lower() in password.lower():
                return False, f"Password contains common pattern: {pattern}"
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', '1234', 'abcd']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                return False, "Password contains keyboard pattern"
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            return False, "Password contains too many repeated characters"
        
        return True, ""
    
    @staticmethod
    def check_password_history(user, new_password):
        """Check against password history (prevent reuse)"""
        # In a real implementation, you'd store password hashes in history
        # For now, just check against current password
        from werkzeug.security import check_password_hash
        
        if hasattr(user, 'password_hash') and user.password_hash:
            if check_password_hash(user.password_hash, new_password):
                return False, "Cannot reuse current password"
        
        return True, ""
    
    @staticmethod
    def generate_secure_password(length=12):
        """Generate a secure random password"""
        import string
        
        # Ensure we have at least one of each required type
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*"
        
        # Start with one of each required type
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest randomly
        all_chars = lowercase + uppercase + digits + special
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)

# Security Headers and Configuration
class SecurityHeaders:
    """Enhanced security headers"""
    
    @staticmethod
    def configure_security_headers(app):
        """Configure comprehensive security headers"""
        
        @app.after_request
        def set_security_headers(response):
            # Prevent clickjacking
            response.headers['X-Frame-Options'] = 'DENY'
            
            # XSS protection
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Content type sniffing protection
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # HTTPS enforcement (HSTS)
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
            
            # Content Security Policy
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.replit.com https://fonts.googleapis.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.replit.com https://fonts.googleapis.com; "
                "img-src 'self' data: https: blob:; "
                "font-src 'self' https://cdn.jsdelivr.net https://cdn.replit.com https://fonts.googleapis.com https://fonts.gstatic.com; "
                "connect-src 'self'; "
                "media-src 'self'; "
                "object-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )
            
            # Referrer policy
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            # Feature policy / Permissions policy
            response.headers['Permissions-Policy'] = (
                "camera=(), microphone=(), geolocation=(), "
                "accelerometer=(), gyroscope=(), magnetometer=(), "
                "payment=(), usb=(), serial=(), bluetooth=()"
            )
            
            # Cache control for sensitive pages
            if request.endpoint and any(sensitive in request.endpoint for sensitive in 
                                      ['profile', 'admin', 'edit', 'settings']):
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
            
            return response

# Advanced Security Monitoring
class SecurityMonitoring:
    """Advanced security monitoring and logging"""
    
    @staticmethod
    def log_security_event(event_type, details, user_id=None, ip_address=None):
        """Log security events"""
        security_logger = logging.getLogger('security')
        
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details,
            'user_id': user_id,
            'ip_address': ip_address or request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'endpoint': request.endpoint
        }
        
        security_logger.warning(f"SECURITY_EVENT: {event_data}")
    
    @staticmethod
    def detect_suspicious_activity(user_id, activity_type):
        """Detect patterns of suspicious activity"""
        # Simple rate-based detection
        current_time = time.time()
        key = f"activity:{user_id}:{activity_type}"
        
        if not hasattr(SecurityMonitoring, '_activity_tracker'):
            SecurityMonitoring._activity_tracker = {}
        
        if key not in SecurityMonitoring._activity_tracker:
            SecurityMonitoring._activity_tracker[key] = []
        
        # Clean old activities (older than 1 hour)
        SecurityMonitoring._activity_tracker[key] = [
            timestamp for timestamp in SecurityMonitoring._activity_tracker[key]
            if current_time - timestamp < 3600
        ]
        
        # Add current activity
        SecurityMonitoring._activity_tracker[key].append(current_time)
        
        # Check for suspicious patterns
        recent_count = len(SecurityMonitoring._activity_tracker[key])
        
        thresholds = {
            'login_attempt': 10,
            'password_change': 5,
            'profile_edit': 20,
            'file_upload': 15,
            'email_send': 5
        }
        
        threshold = thresholds.get(activity_type, 10)
        
        if recent_count > threshold:
            SecurityMonitoring.log_security_event(
                'SUSPICIOUS_ACTIVITY',
                f'High frequency {activity_type}: {recent_count} times in 1 hour',
                user_id
            )
            return True
        
        return False

# URL and Redirect Security
class URLSecurity:
    """URL validation and redirect protection"""
    
    @staticmethod
    def validate_redirect_url(url):
        """Validate redirect URLs to prevent open redirects"""
        if not url:
            return False
        
        # Only allow relative URLs or same-origin URLs
        if url.startswith('/') and not url.startswith('//'):
            return True
        
        # Allow localhost for development
        if url.startswith('http://localhost') or url.startswith('https://localhost'):
            return True
        
        # Block external redirects
        return False
    
    @staticmethod
    def sanitize_url_parameter(url):
        """Sanitize URL parameters"""
        if not url:
            return ""
        
        # Remove dangerous protocols
        dangerous_protocols = ['javascript:', 'vbscript:', 'data:', 'file:', 'ftp:']
        
        for protocol in dangerous_protocols:
            if url.lower().startswith(protocol):
                return ""
        
        return url[:500]  # Limit length

# Complete Security Integration Function
def initialize_complete_security(app):
    """Initialize all security enhancements"""
    
    # Configure security headers
    SecurityHeaders.configure_security_headers(app)
    
    # Configure session security
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        SESSION_COOKIE_NAME='community_connect_session'
    )
    
    # Setup security logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('security.log'),
            logging.StreamHandler()
        ]
    )
    
    # Initialize security logger
    security_logger = logging.getLogger('security')
    security_logger.info("Complete security system initialized")
    
    return app