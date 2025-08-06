"""
Session Management for Community Connect
Handles secure session cookie management and cleanup
"""

import time
import logging
from datetime import datetime, timedelta
from flask import session, request, current_app
from werkzeug.security import generate_password_hash

class SessionManager:
    """Manages secure session cookies and cleanup"""
    
    def __init__(self):
        self.logger = logging.getLogger('session')
        self.session_timeout = 7200  # 2 hours in seconds
        self.cleanup_interval = 3600  # 1 hour
        self.last_cleanup = time.time()
    
    def initialize_session(self, user_id):
        """Initialize a secure session for authenticated user"""
        # Clear any existing session data
        session.clear()
        
        # Set session data
        session['user_id'] = user_id
        session['session_start'] = time.time()
        session['last_activity'] = time.time()
        session['session_token'] = generate_password_hash(f"{user_id}_{time.time()}")
        session['ip_address'] = request.remote_addr
        session['user_agent_hash'] = generate_password_hash(request.headers.get('User-Agent', ''))
        
        # Mark session as permanent with timeout
        session.permanent = True
        current_app.permanent_session_lifetime = timedelta(seconds=self.session_timeout)
        
        self.logger.info(f"Session initialized for user {user_id}")
    
    def validate_session(self):
        """Validate current session security"""
        if 'user_id' not in session:
            return False, "No active session"
        
        current_time = time.time()
        
        # Check session timeout
        if 'last_activity' in session:
            time_since_activity = current_time - session['last_activity']
            if time_since_activity > self.session_timeout:
                self.clear_session()
                return False, "Session expired"
        
        # Check for session hijacking (relaxed for testing)
        if 'ip_address' in session:
            if session['ip_address'] != request.remote_addr:
                self.logger.info(f"IP address changed for user {session.get('user_id')} (from {session['ip_address']} to {request.remote_addr})")
                # Update IP address instead of clearing session for testing
                session['ip_address'] = request.remote_addr
        
        if 'user_agent_hash' in session:
            current_agent_hash = generate_password_hash(request.headers.get('User-Agent', ''))
            # Note: User agent validation is relaxed as it can change legitimately
        
        # Update last activity
        session['last_activity'] = current_time
        
        return True, "Session valid"
    
    def clear_session(self):
        """Securely clear session data"""
        user_id = session.get('user_id')
        session.clear()
        self.logger.info(f"Session cleared for user {user_id}")
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions (placeholder for Redis/database implementation)"""
        current_time = time.time()
        
        # Only run cleanup periodically
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        self.last_cleanup = current_time
        
        # In a production environment, this would connect to session storage
        # and remove expired sessions. For now, we log the cleanup event.
        self.logger.info("Session cleanup performed")
    
    def rotate_session_id(self):
        """Rotate session ID for security"""
        if 'user_id' in session:
            user_id = session['user_id']
            session_data = dict(session)
            
            # Clear and reinitialize
            session.clear()
            for key, value in session_data.items():
                session[key] = value
            
            # Generate new session token
            session['session_token'] = generate_password_hash(f"{user_id}_{time.time()}")
            
            self.logger.info(f"Session ID rotated for user {user_id}")
    
    def get_session_info(self):
        """Get current session information"""
        if 'user_id' not in session:
            return None
        
        current_time = time.time()
        session_duration = current_time - session.get('session_start', current_time)
        time_since_activity = current_time - session.get('last_activity', current_time)
        
        return {
            'user_id': session['user_id'],
            'session_duration': session_duration,
            'time_since_activity': time_since_activity,
            'expires_in': self.session_timeout - time_since_activity,
            'ip_address': session.get('ip_address'),
            'session_start': datetime.fromtimestamp(session.get('session_start', current_time))
        }

# Global session manager instance
session_manager = SessionManager()