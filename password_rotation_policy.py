"""
Enhanced Security Feature 3: Password Rotation Policy
Enforces regular password changes for admin accounts and tracks password history
"""

from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from flask import flash
import logging

# Enhanced Security Feature 3: Password Rotation Policy
class PasswordRotationPolicy:
    """Manages password rotation policies for different user types"""
    
    # Password rotation requirements by user type (in days)
    ROTATION_POLICIES = {
        'admin': 90,        # Admins must change password every 90 days
        'organizer': 180,   # Organizers every 6 months
        'volunteer': 365,   # Volunteers yearly
        'elderly': None     # No forced rotation for elderly users
    }
    
    # Number of previous passwords to remember
    PASSWORD_HISTORY_COUNT = 5
    
    @staticmethod
    def is_password_rotation_required(user):
        """Check if user needs to rotate password"""
        if not user or user.user_type not in PasswordRotationPolicy.ROTATION_POLICIES:
            return False
        
        rotation_days = PasswordRotationPolicy.ROTATION_POLICIES[user.user_type]
        if not rotation_days:  # No rotation required
            return False
        
        # Check if password_changed_at field exists and has a value
        if not hasattr(user, 'password_changed_at') or not user.password_changed_at:
            # If no password change date recorded, require rotation for admin
            return user.user_type == 'admin'
        
        # Check if password is older than required rotation period
        rotation_deadline = user.password_changed_at + timedelta(days=rotation_days)
        return datetime.now() > rotation_deadline
    
    @staticmethod
    def get_password_expiry_warning(user):
        """Get warning message for upcoming password expiration"""
        if not user or user.user_type not in PasswordRotationPolicy.ROTATION_POLICIES:
            return None
        
        rotation_days = PasswordRotationPolicy.ROTATION_POLICIES[user.user_type]
        if not rotation_days:
            return None
        
        if not hasattr(user, 'password_changed_at') or not user.password_changed_at:
            return None
        
        rotation_deadline = user.password_changed_at + timedelta(days=rotation_days)
        warning_deadline = rotation_deadline - timedelta(days=14)  # Warn 14 days before
        
        if datetime.now() > warning_deadline:
            days_left = (rotation_deadline - datetime.now()).days
            if days_left > 0:
                return f"Your password will expire in {days_left} days. Please change it soon."
            else:
                return "Your password has expired. Please change it immediately."
        
        return None
    
    @staticmethod
    def validate_password_history(user, new_password):
        """Check if password was used recently"""
        if not hasattr(user, 'password_history') or not user.password_history:
            return True, ""
        
        # Parse password history (JSON string of hashed passwords)
        try:
            import json
            history = json.loads(user.password_history)
            
            # Check against recent passwords
            for old_hash in history[-PasswordRotationPolicy.PASSWORD_HISTORY_COUNT:]:
                if check_password_hash(old_hash, new_password):
                    return False, f"Cannot reuse any of your last {PasswordRotationPolicy.PASSWORD_HISTORY_COUNT} passwords"
            
            return True, ""
        except:
            # If parsing fails, allow password change
            return True, ""
    
    @staticmethod
    def update_password_history(user, new_password_hash):
        """Update user's password history"""
        try:
            import json
            
            # Get existing history or create new
            if hasattr(user, 'password_history') and user.password_history:
                history = json.loads(user.password_history)
            else:
                history = []
            
            # Add new password hash
            history.append(new_password_hash)
            
            # Keep only last N passwords
            history = history[-PasswordRotationPolicy.PASSWORD_HISTORY_COUNT:]
            
            # Update user record
            user.password_history = json.dumps(history)
            user.password_changed_at = datetime.now()
            
            logging.info(f"Password history updated for user {user.id} ({user.user_type})")
            
        except Exception as e:
            logging.error(f"Failed to update password history: {e}")
    
    @staticmethod
    def enforce_rotation_policy():
        """Check all users for password rotation requirements"""
        from models import User, db
        
        users_needing_rotation = []
        
        # Get all admin and organizer users
        users = User.query.filter(User.user_type.in_(['admin', 'organizer', 'volunteer'])).all()
        
        for user in users:
            if PasswordRotationPolicy.is_password_rotation_required(user):
                users_needing_rotation.append({
                    'id': user.id,
                    'email': getattr(user, 'email', 'N/A'),
                    'user_type': user.user_type,
                    'last_changed': user.password_changed_at if hasattr(user, 'password_changed_at') else None
                })
        
        if users_needing_rotation:
            logging.warning(f"Users requiring password rotation: {users_needing_rotation}")
        
        return users_needing_rotation

def password_rotation_required(f):
    """Decorator to check if password rotation is required"""
    from functools import wraps
    from flask import redirect, url_for
    from flask_login import current_user
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if PasswordRotationPolicy.is_password_rotation_required(current_user):
                flash('Your password has expired. Please change it to continue.', 'warning')
                return redirect(url_for('profile.change_password'))
            
            # Show warning if password expires soon
            warning = PasswordRotationPolicy.get_password_expiry_warning(current_user)
            if warning:
                flash(warning, 'info')
        
        return f(*args, **kwargs)
    
    return decorated_function