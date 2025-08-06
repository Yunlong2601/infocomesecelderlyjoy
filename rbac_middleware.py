"""
Enterprise-Grade RBAC Security Middleware for Community Connect

This middleware provides real-time security monitoring and enforcement
for all HTTP requests, implementing defense-in-depth security patterns.

Security Features:
- Request-level security validation
- Real-time threat detection
- Automated security response
- Comprehensive security logging
- Rate limiting and abuse prevention
"""

from flask import request, session, current_app, abort, jsonify
from flask_login import current_user
from datetime import datetime, timedelta
import logging
import json
import re
from collections import defaultdict

# Enhanced middleware logging
middleware_logger = logging.getLogger('rbac_middleware')
middleware_logger.setLevel(logging.INFO)

class RBACSecurityMiddleware:
    """Enterprise-grade security middleware with real-time monitoring"""
    
    def __init__(self, app=None):
        self.app = app
        self.security_events = []
        self.request_patterns = defaultdict(list)
        self.blocked_ips = set()
        self.suspicious_patterns = self._define_suspicious_patterns()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        app.before_request(self.before_request_security_check)
        app.after_request(self.after_request_security_log)
        app.teardown_request(self.cleanup_request_data)
    
    def _define_suspicious_patterns(self):
        """Define patterns that indicate potential security threats"""
        return {
            'sql_injection': [
                r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
                r'(--|\#|/\*|\*/)',
                r'(\bOR\b.*=.*\bOR\b)',
                r'(\bAND\b.*=.*\bAND\b)',
                r'(\bUNION\b.*\bSELECT\b)'
            ],
            'xss_attempts': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'<iframe[^>]*>.*?</iframe>'
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\',
                r'/etc/passwd',
                r'/proc/self/environ'
            ],
            'privilege_escalation': [
                r'admin',
                r'root',
                r'superuser',
                r'privilege',
                r'escalate'
            ]
        }
    
    def before_request_security_check(self):
        """Comprehensive security check before processing request"""
        try:
            # Skip security checks for static files
            if request.path.startswith('/static/'):
                return None
            
            # Check if IP is blocked
            client_ip = self._get_client_ip()
            if client_ip in self.blocked_ips:
                middleware_logger.warning(f"BLOCKED_IP_ACCESS: {client_ip} attempted access to {request.path}")
                abort(403)
            
            # Rate limiting check
            if not self._check_rate_limit(client_ip):
                middleware_logger.warning(f"RATE_LIMIT_EXCEEDED: {client_ip} exceeded rate limit")
                abort(429)
            
            # Malicious pattern detection
            threats_detected = self._detect_malicious_patterns()
            if threats_detected:
                self._handle_security_threat(threats_detected, client_ip)
                abort(403)
            
            # RBAC validation for protected routes
            if self._is_protected_route(request.path):
                if not self._validate_rbac_access():
                    middleware_logger.warning(
                        f"RBAC_ACCESS_DENIED: User {current_user.id if current_user.is_authenticated else 'anonymous'} "
                        f"denied access to {request.path}"
                    )
                    abort(403)
            
            # Session security validation (temporarily disabled for debugging)
            # if current_user.is_authenticated:
            #     if not self._validate_session_security():
            #         middleware_logger.warning(f"SESSION_SECURITY_VIOLATION: User {current_user.id}")
            #         session.clear()
            #         abort(401)
            
            # Log successful security validation
            self._log_security_event('REQUEST_VALIDATED', {
                'path': request.path,
                'method': request.method,
                'user_id': current_user.id if current_user.is_authenticated else None,
                'ip': client_ip
            })
            
        except Exception as e:
            middleware_logger.error(f"MIDDLEWARE_ERROR: {str(e)}")
            # Don't block requests due to middleware errors, but log them
            return None
    
    def after_request_security_log(self, response):
        """Security logging after request processing"""
        try:
            client_ip = self._get_client_ip()
            
            # Log response for security monitoring
            log_data = {
                'path': request.path,
                'method': request.method,
                'status_code': response.status_code,
                'user_id': current_user.id if current_user.is_authenticated else None,
                'ip': client_ip,
                'timestamp': datetime.utcnow().isoformat(),
                'user_agent': request.headers.get('User-Agent', '')[:200]
            }
            
            # Log suspicious response patterns
            if response.status_code in [403, 401, 429]:
                middleware_logger.warning(f"SECURITY_RESPONSE: {json.dumps(log_data)}")
            else:
                middleware_logger.info(f"REQUEST_COMPLETED: {json.dumps(log_data)}")
            
            # Update request tracking
            self._update_request_tracking(client_ip)
            
        except Exception as e:
            middleware_logger.error(f"AFTER_REQUEST_ERROR: {str(e)}")
        
        return response
    
    def cleanup_request_data(self, exception):
        """Clean up request-specific data"""
        # Clean up temporary data, handle exceptions
        if exception:
            middleware_logger.error(f"REQUEST_EXCEPTION: {str(exception)}")
    
    def _get_client_ip(self):
        """Get real client IP address handling proxies"""
        # Check for forwarded IP first (behind proxy/load balancer)
        forwarded_ips = request.headers.get('X-Forwarded-For')
        if forwarded_ips:
            return forwarded_ips.split(',')[0].strip()
        
        # Check for real IP header
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        # Fall back to remote address
        return request.remote_addr or '127.0.0.1'
    
    def _check_rate_limit(self, client_ip, max_requests=100, time_window=300):
        """Advanced rate limiting with sliding window"""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=time_window)
        
        # Clean old requests
        self.request_patterns[client_ip] = [
            req_time for req_time in self.request_patterns[client_ip]
            if req_time > cutoff
        ]
        
        # Add current request
        self.request_patterns[client_ip].append(now)
        
        # Check if rate limit exceeded
        if len(self.request_patterns[client_ip]) > max_requests:
            # Add to suspicious IPs for enhanced monitoring
            self._add_suspicious_ip(client_ip, 'RATE_LIMIT_EXCEEDED')
            return False
        
        return True
    
    def _detect_malicious_patterns(self):
        """Detect malicious patterns in request data"""
        threats = []
        
        # Check URL parameters
        for param, value in request.args.items():
            for threat_type, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, str(value), re.IGNORECASE):
                        threats.append({
                            'type': threat_type,
                            'location': 'url_param',
                            'param': param,
                            'pattern': pattern,
                            'value': str(value)[:100]  # Limit logged value length
                        })
        
        # Check POST data
        if request.method == 'POST' and request.form:
            for field, value in request.form.items():
                for threat_type, patterns in self.suspicious_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, str(value), re.IGNORECASE):
                            threats.append({
                                'type': threat_type,
                                'location': 'form_data',
                                'field': field,
                                'pattern': pattern,
                                'value': str(value)[:100]
                            })
        
        # Check headers for suspicious content
        suspicious_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
        for header in suspicious_headers:
            value = request.headers.get(header, '')
            for threat_type, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        threats.append({
                            'type': threat_type,
                            'location': 'header',
                            'header': header,
                            'pattern': pattern,
                            'value': value[:100]
                        })
        
        return threats
    
    def _is_protected_route(self, path):
        """Check if route requires RBAC protection"""
        protected_prefixes = [
            '/admin/',
            '/organizer/',
            '/volunteer/', 
            '/profile/',
            '/events/rsvp',
            '/events/volunteer',
            '/events/create',
            '/events/edit'
        ]
        
        return any(path.startswith(prefix) for prefix in protected_prefixes)
    
    def _validate_rbac_access(self):
        """Validate RBAC access for current request"""
        if not current_user.is_authenticated:
            return False
        
        path = request.path
        user_type = current_user.user_type
        
        # Define access rules
        access_rules = {
            '/admin/': ['admin'],
            '/organizer/': ['organizer', 'admin'],
            '/volunteer/': ['volunteer', 'admin'],
            '/profile/': ['elderly', 'admin'],
            '/events/rsvp': ['elderly', 'volunteer'],
            '/events/volunteer': ['volunteer'],
            '/events/create': ['organizer', 'admin'],
            '/events/edit': ['organizer', 'admin']
        }
        
        # Check access rules
        for route_prefix, allowed_roles in access_rules.items():
            if path.startswith(route_prefix):
                return user_type in allowed_roles
        
        # Default allow for non-protected routes
        return True
    
    def _validate_session_security(self):
        """Validate session security and integrity"""
        try:
            # Check session consistency
            if 'user_id' in session and session['user_id'] != current_user.id:
                return False
            
            # Check session timeout
            if 'last_activity' in session:
                try:
                    last_activity_str = session['last_activity']
                    if isinstance(last_activity_str, str):
                        last_activity = datetime.fromisoformat(last_activity_str)
                        if datetime.utcnow() - last_activity > timedelta(hours=8):
                            return False
                except (ValueError, TypeError):
                    # Invalid datetime format, reset session activity
                    pass
            
            # Update session tracking
            session['last_activity'] = datetime.utcnow().isoformat()
            session['session_ip'] = self._get_client_ip()
            
            return True
            
        except Exception as e:
            middleware_logger.error(f"SESSION_VALIDATION_ERROR: {str(e)}")
            return False
    
    def _handle_security_threat(self, threats, client_ip):
        """Handle detected security threats"""
        threat_summary = {
            'ip': client_ip,
            'timestamp': datetime.utcnow().isoformat(),
            'threats': threats,
            'path': request.path,
            'method': request.method,
            'user_agent': request.headers.get('User-Agent', '')[:200]
        }
        
        # Log the security threat
        middleware_logger.warning(f"SECURITY_THREAT_DETECTED: {json.dumps(threat_summary)}")
        
        # Add to blocked IPs for critical threats
        critical_threats = ['sql_injection', 'xss_attempts', 'privilege_escalation']
        if any(threat['type'] in critical_threats for threat in threats):
            self.blocked_ips.add(client_ip)
            middleware_logger.critical(f"IP_BLOCKED: {client_ip} due to critical security threats")
        
        # Store threat for analysis
        self.security_events.append(threat_summary)
    
    def _add_suspicious_ip(self, ip, reason):
        """Add IP to suspicious activity monitoring"""
        middleware_logger.info(f"SUSPICIOUS_ACTIVITY: {ip} - {reason}")
        # Could integrate with external threat intelligence here
    
    def _update_request_tracking(self, client_ip):
        """Update request tracking for analytics"""
        # Clean old tracking data periodically
        if len(self.request_patterns[client_ip]) > 1000:
            self.request_patterns[client_ip] = self.request_patterns[client_ip][-500:]
    
    def _log_security_event(self, event_type, data):
        """Log security events for monitoring"""
        event = {
            'event_type': event_type,
            'timestamp': datetime.utcnow().isoformat(),
            'data': data
        }
        
        middleware_logger.info(f"SECURITY_EVENT: {json.dumps(event)}")
    
    def get_security_stats(self):
        """Get security statistics for monitoring"""
        return {
            'blocked_ips': len(self.blocked_ips),
            'security_events': len(self.security_events),
            'active_sessions': len(self.request_patterns),
            'recent_threats': len([
                event for event in self.security_events
                if 'timestamp' in event and isinstance(event['timestamp'], str) and
                   datetime.fromisoformat(event['timestamp']) > 
                   datetime.utcnow() - timedelta(hours=1)
            ])
        }

# Global middleware instance
rbac_middleware = RBACSecurityMiddleware()