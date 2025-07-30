"""
Comprehensive Security Enhancements for Community Connect
Addresses OWASP Top 10 vulnerabilities and security best practices
"""

import os
import hashlib
import secrets
import logging
import time
from datetime import datetime, timedelta
from flask import request, session, current_app
import re

# Configure comprehensive security logging
def setup_security_logging():
    """Configure comprehensive security logging"""
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    
    # Create file handler for security events
    handler = logging.FileHandler('security.log')
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    security_logger.addHandler(handler)
    
    return security_logger

# Cryptographic security enhancements
class CryptographicSecurity:
    """Handles cryptographic operations securely"""
    
    @staticmethod
    def generate_secure_token(length=32):
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_data(data, salt=None):
        """Secure data hashing with salt"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Use PBKDF2 for password-like data
        from werkzeug.security import generate_password_hash
        return generate_password_hash(data)
    
    @staticmethod
    def validate_session_integrity():
        """Validate session integrity"""
        if 'session_token' not in session:
            session['session_token'] = CryptographicSecurity.generate_secure_token()
        
        # Check session timeout (30 minutes)
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=30):
                session.clear()
                return False
        
        session['last_activity'] = datetime.now().isoformat()
        return True

# SQL Injection prevention
class SQLInjectionPrevention:
    """Prevents SQL injection attacks"""
    
    @staticmethod
    def sanitize_sql_input(input_string):
        """Sanitize input for SQL queries"""
        if not input_string:
            return ""
        
        # Remove SQL injection patterns
        dangerous_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"('|(\\'))",
            r"(;|--|\|\|)",
            r"(\bOR\b.*\b=\b)",
            r"(\bAND\b.*\b=\b)"
        ]
        
        sanitized = str(input_string)
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)
        
        return sanitized.strip()
    
    @staticmethod
    def validate_query_parameters(params):
        """Validate and sanitize query parameters"""
        sanitized_params = {}
        for key, value in params.items():
            if isinstance(value, str):
                sanitized_params[key] = SQLInjectionPrevention.sanitize_sql_input(value)
            else:
                sanitized_params[key] = value
        return sanitized_params

# Security configuration
class SecurityConfiguration:
    """Manages security configuration settings"""
    
    @staticmethod
    def configure_app_security(app):
        """Configure Flask app security settings"""
        
        # Secure headers
        @app.after_request
        def set_security_headers(response):
            # Prevent clickjacking
            response.headers['X-Frame-Options'] = 'DENY'
            
            # XSS protection
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Content type sniffing protection
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # HTTPS enforcement
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
            # Content Security Policy
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.replit.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.replit.com; "
                "img-src 'self' data: https:; "
                "font-src 'self' https://cdn.jsdelivr.net https://cdn.replit.com;"
            )
            
            # Referrer policy
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            return response
        
        # Session security
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',
            PERMANENT_SESSION_LIFETIME=timedelta(hours=2)
        )

# Authentication security
class AuthenticationSecurity:
    """Enhanced authentication security"""
    
    @staticmethod
    def rate_limit_check(identifier, max_attempts=5, window_minutes=15):
        """Rate limiting for login attempts"""
        cache_key = f"login_attempts_{identifier}"
        
        # Simple in-memory rate limiting (in production, use Redis)
        if not hasattr(AuthenticationSecurity, '_attempt_cache'):
            AuthenticationSecurity._attempt_cache = {}
        
        now = time.time()
        window_start = now - (window_minutes * 60)
        
        # Clean old attempts
        if cache_key in AuthenticationSecurity._attempt_cache:
            AuthenticationSecurity._attempt_cache[cache_key] = [
                attempt for attempt in AuthenticationSecurity._attempt_cache[cache_key]
                if attempt > window_start
            ]
        else:
            AuthenticationSecurity._attempt_cache[cache_key] = []
        
        # Check if limit exceeded
        if len(AuthenticationSecurity._attempt_cache[cache_key]) >= max_attempts:
            return False
        
        # Record attempt
        AuthenticationSecurity._attempt_cache[cache_key].append(now)
        return True
    
    @staticmethod
    def validate_password_strength(password):
        """Validate password meets security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        
        return True, "Password is strong"

# SSRF prevention
class SSRFPrevention:
    """Prevents Server-Side Request Forgery attacks"""
    
    BLOCKED_NETWORKS = [
        '127.0.0.0/8',    # Localhost
        '10.0.0.0/8',     # Private networks
        '172.16.0.0/12',  # Private networks
        '192.168.0.0/16', # Private networks
        '169.254.0.0/16', # Link-local
        '::1/128',        # IPv6 localhost
        'fc00::/7',       # IPv6 private
    ]
    
    @staticmethod
    def validate_url(url):
        """Validate URL to prevent SSRF attacks"""
        import urllib.parse
        import ipaddress
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Only allow HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False, "Only HTTP/HTTPS URLs are allowed"
            
            # Check for suspicious hostnames
            hostname = parsed.hostname
            if not hostname:
                return False, "Invalid hostname"
            
            # Check for IP addresses in blocked ranges
            try:
                ip = ipaddress.ip_address(hostname)
                for network in SSRFPrevention.BLOCKED_NETWORKS:
                    if ip in ipaddress.ip_network(network):
                        return False, "Access to private networks is not allowed"
            except ipaddress.AddressValueError:
                # Not an IP address, continue with hostname validation
                pass
            
            # Block localhost variations
            blocked_hosts = ['localhost', '0.0.0.0', '127.0.0.1']
            if hostname.lower() in blocked_hosts:
                return False, "Access to localhost is not allowed"
            
            return True, "URL is safe"
            
        except Exception:
            return False, "Invalid URL format"

# Data integrity validation
class DataIntegrityValidation:
    """Validates data integrity and prevents tampering"""
    
    @staticmethod
    def generate_checksum(data):
        """Generate checksum for data integrity"""
        return hashlib.sha256(str(data).encode()).hexdigest()
    
    @staticmethod
    def validate_form_integrity(form_data, expected_fields):
        """Validate form data integrity"""
        # Check for required fields
        for field in expected_fields:
            if field not in form_data:
                return False, f"Missing required field: {field}"
        
        # Check for unexpected fields (potential tampering)
        for field in form_data:
            if field not in expected_fields and not field.startswith('csrf_'):
                return False, f"Unexpected field detected: {field}"
        
        return True, "Form data is valid"

# Component security scanner
class ComponentSecurity:
    """Checks for vulnerable components"""
    
    @staticmethod
    def get_installed_packages():
        """Get list of installed Python packages"""
        try:
            import pkg_resources
            packages = []
            for dist in pkg_resources.working_set:
                packages.append({
                    'name': dist.project_name,
                    'version': dist.version
                })
            return packages
        except ImportError:
            return []
    
    @staticmethod
    def check_security_headers():
        """Check if security headers are properly configured"""
        required_headers = [
            'X-Frame-Options',
            'X-XSS-Protection', 
            'X-Content-Type-Options',
            'Content-Security-Policy'
        ]
        
        # This would be checked during runtime
        return required_headers

# Monitoring and alerting
class SecurityMonitoring:
    """Security monitoring and alerting system"""
    
    @staticmethod
    def log_security_event(event_type, details, user_id=None, ip_address=None):
        """Log security events for monitoring"""
        security_logger = logging.getLogger('security')
        
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details,
            'user_id': user_id,
            'ip_address': ip_address or request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None
        }
        
        security_logger.warning(f"SECURITY_EVENT: {event_data}")
        
        # In production, send to SIEM or monitoring system
        return event_data
    
    @staticmethod
    def detect_anomalies(user_id, action):
        """Simple anomaly detection"""
        # Track user actions for anomaly detection
        cache_key = f"user_actions_{user_id}"
        
        if not hasattr(SecurityMonitoring, '_action_cache'):
            SecurityMonitoring._action_cache = {}
        
        now = time.time()
        if cache_key not in SecurityMonitoring._action_cache:
            SecurityMonitoring._action_cache[cache_key] = []
        
        # Add current action
        SecurityMonitoring._action_cache[cache_key].append({
            'action': action,
            'timestamp': now
        })
        
        # Keep only last hour of actions
        hour_ago = now - 3600
        SecurityMonitoring._action_cache[cache_key] = [
            act for act in SecurityMonitoring._action_cache[cache_key]
            if act['timestamp'] > hour_ago
        ]
        
        # Check for suspicious activity (more than 100 actions per hour)
        if len(SecurityMonitoring._action_cache[cache_key]) > 100:
            SecurityMonitoring.log_security_event(
                'SUSPICIOUS_ACTIVITY',
                f'User {user_id} performed {len(SecurityMonitoring._action_cache[cache_key])} actions in the last hour',
                user_id=user_id
            )
            return True
        
        return False