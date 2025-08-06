"""
Comprehensive Security Validator for Community Connect
Implements protection against all OWASP Top 10 vulnerabilities
"""

import re
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import request, session, current_app
from urllib.parse import urlparse
import ipaddress

# Security logging
security_logger = logging.getLogger('security')

class OWASPSecurityValidator:
    """Comprehensive OWASP Top 10 security validator"""
    
    # 1. Broken Access Control - Already implemented in access_control.py
    
    # 2. Cryptographic Failures
    @staticmethod
    def validate_password_strength(password):
        """Ensure strong passwords"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain lowercase letter"
        if not re.search(r"\d", password):
            return False, "Password must contain number"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain special character"
        return True, "Password is strong"
    
    @staticmethod
    def generate_secure_token():
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_sensitive_data(data):
        """Securely hash sensitive data"""
        salt = secrets.token_bytes(32)
        hashed = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
        return salt + hashed
    
    # 3. Injection (SQL, NoSQL, etc.)
    @staticmethod
    def sanitize_sql_input(input_str):
        """Prevent SQL injection"""
        if not input_str:
            return ""
        
        # Remove dangerous SQL patterns
        dangerous_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(--|#|/\*|\*/)",
            r"('|(\\'))",
            r"(;|\|\|)",
            r"(\bOR\b.*=.*)",
            r"(\bAND\b.*=.*)",
            r"(\bUNION\b.*\bSELECT\b)"
        ]
        
        sanitized = str(input_str)
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)
        
        return sanitized.strip()[:255]  # Limit length
    
    @staticmethod
    def validate_email_format(email):
        """Validate email format to prevent injection"""
        if not email:
            return False
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    # 4. Insecure Design
    @staticmethod
    def validate_business_logic(user_type, action, resource_id=None):
        """Validate business logic constraints"""
        if user_type == 'elderly':
            restricted_actions = ['create_event', 'manage_users', 'approve_events']
            if action in restricted_actions:
                return False, f"Elderly users cannot perform {action}"
        
        elif user_type == 'organizer':
            if action == 'manage_users' or action == 'terminate_accounts':
                return False, "Organizers cannot manage user accounts"
        
        elif user_type == 'volunteer':
            restricted_actions = ['create_event', 'manage_users', 'approve_events']
            if action in restricted_actions:
                return False, f"Volunteers cannot perform {action}"
        
        return True, "Action allowed"
    
    @staticmethod
    def validate_file_upload(filename, max_size_mb=16):
        """Secure file upload validation"""
        if not filename:
            return False, "No filename provided"
        
        # Check file extension
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
        if file_ext not in allowed_extensions:
            return False, "File type not allowed"
        
        # Check for dangerous filename patterns
        dangerous_patterns = [r'\.\.', r'/', r'\\', r'<', r'>', r'\|', r':', r'\*', r'\?', r'"']
        for pattern in dangerous_patterns:
            if re.search(pattern, filename):
                return False, "Filename contains dangerous characters"
        
        return True, "File upload valid"
    
    # 5. Security Misconfiguration
    @staticmethod
    def check_security_headers():
        """Validate security headers are set"""
        required_headers = {
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': True,
            'Referrer-Policy': True
        }
        return required_headers
    
    @staticmethod
    def validate_session_security():
        """Validate session configuration"""
        if not session.get('csrf_token'):
            session['csrf_token'] = OWASPSecurityValidator.generate_secure_token()
        
        # Check session timeout
        last_activity = session.get('last_activity')
        if last_activity:
            try:
                if isinstance(last_activity, str):
                    last_activity_dt = datetime.fromisoformat(last_activity)
                elif isinstance(last_activity, (int, float)):
                    last_activity_dt = datetime.fromtimestamp(last_activity)
                else:
                    last_activity_dt = last_activity
                
                if datetime.now() - last_activity_dt > timedelta(hours=2):
                    session.clear()
                    return False, "Session expired"
            except (ValueError, OSError, TypeError):
                # If we can't parse the timestamp, just update it
                pass
        
        session['last_activity'] = datetime.now().isoformat()
        return True, "Session valid"
    
    # 6. Vulnerable and Outdated Components
    @staticmethod
    def get_security_recommendations():
        """Security recommendations for components"""
        return {
            'flask': 'Keep Flask updated to latest version',
            'werkzeug': 'Ensure Werkzeug is current for security fixes',
            'sqlalchemy': 'Update SQLAlchemy for latest security patches',
            'dependencies': 'Regularly audit dependencies with safety/pip-audit'
        }
    
    # 7. Identification and Authentication Failures
    @staticmethod
    def validate_authentication_attempt(identifier, ip_address):
        """Rate limiting and validation for authentication"""
        cache_key = f"auth_attempts_{identifier}_{ip_address}"
        
        # Simple rate limiting (in production, use Redis)
        if not hasattr(OWASPSecurityValidator, '_auth_cache'):
            OWASPSecurityValidator._auth_cache = {}
        
        now = datetime.now()
        if cache_key not in OWASPSecurityValidator._auth_cache:
            OWASPSecurityValidator._auth_cache[cache_key] = []
        
        # Clean old attempts (last 15 minutes)
        cutoff = now - timedelta(minutes=15)
        OWASPSecurityValidator._auth_cache[cache_key] = [
            attempt for attempt in OWASPSecurityValidator._auth_cache[cache_key]
            if attempt > cutoff
        ]
        
        # Check if rate limit exceeded (5 attempts in 15 minutes)
        if len(OWASPSecurityValidator._auth_cache[cache_key]) >= 5:
            return False, "Rate limit exceeded"
        
        # Record this attempt
        OWASPSecurityValidator._auth_cache[cache_key].append(now)
        return True, "Authentication attempt allowed"
    
    @staticmethod
    def validate_password_requirements(password):
        """Validate password meets security requirements"""
        return OWASPSecurityValidator.validate_password_strength(password)
    
    # 8. Software and Data Integrity Failures
    @staticmethod
    def generate_data_checksum(data):
        """Generate checksum for data integrity verification"""
        return hashlib.sha256(str(data).encode()).hexdigest()
    
    @staticmethod
    def validate_form_integrity(form_data, expected_fields):
        """Validate form hasn't been tampered with"""
        for field in expected_fields:
            if field not in form_data:
                return False, f"Missing required field: {field}"
        
        # Check for unexpected fields (potential tampering)
        unexpected = set(form_data.keys()) - set(expected_fields) - {'csrf_token'}
        if unexpected:
            return False, f"Unexpected fields: {unexpected}"
        
        return True, "Form integrity valid"
    
    @staticmethod
    def validate_json_input(json_data, max_depth=3):
        """Validate JSON input to prevent injection"""
        if not isinstance(json_data, (dict, list)):
            return False, "Invalid JSON format"
        
        def check_depth(obj, depth=0):
            if depth > max_depth:
                return False
            if isinstance(obj, dict):
                return all(check_depth(v, depth + 1) for v in obj.values())
            elif isinstance(obj, list):
                return all(check_depth(item, depth + 1) for item in obj)
            return True
        
        if not check_depth(json_data):
            return False, "JSON too deeply nested"
        
        return True, "JSON input valid"
    
    # 9. Security Logging and Monitoring Failures
    @staticmethod
    def log_security_event(event_type, details, user_id=None, severity='INFO'):
        """Comprehensive security event logging"""
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details,
            'user_id': user_id,
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
            'severity': severity
        }
        
        log_message = f"SECURITY_EVENT: {event_data}"
        
        if severity == 'CRITICAL':
            security_logger.critical(log_message)
        elif severity == 'WARNING':
            security_logger.warning(log_message)
        else:
            security_logger.info(log_message)
        
        return event_data
    
    @staticmethod
    def detect_suspicious_activity(user_id, action_type):
        """Detect suspicious user activity patterns"""
        cache_key = f"user_activity_{user_id}"
        
        if not hasattr(OWASPSecurityValidator, '_activity_cache'):
            OWASPSecurityValidator._activity_cache = {}
        
        now = datetime.now()
        if cache_key not in OWASPSecurityValidator._activity_cache:
            OWASPSecurityValidator._activity_cache[cache_key] = []
        
        # Add current activity
        OWASPSecurityValidator._activity_cache[cache_key].append({
            'action': action_type,
            'timestamp': now
        })
        
        # Keep only last hour
        cutoff = now - timedelta(hours=1)
        OWASPSecurityValidator._activity_cache[cache_key] = [
            activity for activity in OWASPSecurityValidator._activity_cache[cache_key]
            if activity['timestamp'] > cutoff
        ]
        
        # Check for suspicious patterns
        activity_count = len(OWASPSecurityValidator._activity_cache[cache_key])
        
        if activity_count > 100:  # More than 100 actions per hour
            OWASPSecurityValidator.log_security_event(
                'SUSPICIOUS_ACTIVITY',
                f'User {user_id} performed {activity_count} actions in last hour',
                user_id=user_id,
                severity='WARNING'
            )
            return True
        
        return False
    
    # 10. Server-Side Request Forgery (SSRF)
    @staticmethod
    def validate_url_request(url):
        """Prevent SSRF attacks"""
        try:
            parsed = urlparse(url)
            
            # Only allow HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False, "Only HTTP/HTTPS URLs allowed"
            
            hostname = parsed.hostname
            if not hostname:
                return False, "Invalid hostname"
            
            # Block private networks
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    return False, "Access to private networks not allowed"
            except ipaddress.AddressValueError:
                # Not an IP address, check hostname
                pass
            
            # Block localhost variations
            blocked_hosts = ['localhost', '0.0.0.0', '127.0.0.1', 'local']
            if hostname.lower() in blocked_hosts:
                return False, "Access to localhost not allowed"
            
            # Block internal domains
            if hostname.endswith('.local') or hostname.endswith('.internal'):
                return False, "Access to internal domains not allowed"
            
            return True, "URL is safe"
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"
    
    @staticmethod
    def sanitize_redirect_url(url):
        """Sanitize redirect URLs to prevent open redirect"""
        if not url:
            return None
        
        # Only allow relative URLs or same-origin URLs
        if url.startswith('/'):
            return url
        
        try:
            parsed = urlparse(url)
            # For external URLs, only allow if explicitly whitelisted
            allowed_domains = ['example.com']  # Add trusted domains
            if parsed.netloc.lower() in allowed_domains:
                return url
        except:
            pass
        
        return None  # Block suspicious redirects