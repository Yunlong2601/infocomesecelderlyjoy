"""
Enhanced Security Feature 2: API Rate Limiting Per Endpoint
Prevents abuse and DoS attacks through granular rate limiting
"""

from flask import request, abort, session
import time
from functools import wraps
import logging

# Enhanced Security Feature 2: API Rate Limiting Per Endpoint
class RateLimiter:
    """Advanced rate limiting system for different endpoints"""
    
    # In-memory storage for rate limits (in production, use Redis)
    _requests = {}
    
    @staticmethod
    def is_rate_limited(key, limit, window=60):
        """Check if request should be rate limited"""
        current_time = time.time()
        
        if key not in RateLimiter._requests:
            RateLimiter._requests[key] = []
        
        # Remove old requests outside the window
        RateLimiter._requests[key] = [
            req_time for req_time in RateLimiter._requests[key]
            if current_time - req_time < window
        ]
        
        # Check if limit exceeded
        if len(RateLimiter._requests[key]) >= limit:
            return True
        
        # Add current request
        RateLimiter._requests[key].append(current_time)
        return False

def rate_limit_per_endpoint(limit=30, window=60, per='ip'):
    """
    Enhanced rate limiting decorator for specific endpoints
    
    Args:
        limit: Number of requests allowed
        window: Time window in seconds
        per: Rate limiting key ('ip', 'user', 'session')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine rate limiting key
            if per == 'ip':
                key = f"rate_limit:ip:{request.remote_addr}:{f.__name__}"
            elif per == 'user':
                from flask_login import current_user
                if current_user.is_authenticated:
                    key = f"rate_limit:user:{current_user.id}:{f.__name__}"
                else:
                    key = f"rate_limit:ip:{request.remote_addr}:{f.__name__}"
            elif per == 'session':
                session_id = session.get('session_token', request.remote_addr)
                key = f"rate_limit:session:{session_id}:{f.__name__}"
            else:
                key = f"rate_limit:{request.remote_addr}:{f.__name__}"
            
            # Check rate limit
            if RateLimiter.is_rate_limited(key, limit, window):
                logging.warning(f"Rate limit exceeded for {key}")
                abort(429)  # Too Many Requests
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Specific rate limiters for different endpoint types
def login_rate_limit(limit=5, window=300):  # 5 attempts per 5 minutes
    """Rate limiting for login endpoints"""
    return rate_limit_per_endpoint(limit, window, 'ip')

def api_rate_limit(limit=60, window=60):  # 60 requests per minute
    """Rate limiting for API endpoints"""
    return rate_limit_per_endpoint(limit, window, 'user')

def profile_edit_rate_limit(limit=10, window=300):  # 10 edits per 5 minutes
    """Rate limiting for profile editing"""
    return rate_limit_per_endpoint(limit, window, 'user')

def email_send_rate_limit(limit=3, window=300):  # 3 emails per 5 minutes
    """Rate limiting for email sending"""
    return rate_limit_per_endpoint(limit, window, 'user')

def file_upload_rate_limit(limit=10, window=300):  # 10 uploads per 5 minutes
    """Rate limiting for file uploads"""
    return rate_limit_per_endpoint(limit, window, 'user')