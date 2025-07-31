#!/usr/bin/env python3
"""Test script to register and login an elderly user"""

from app import app, db
from models import User
from werkzeug.security import generate_password_hash
from encryption_manager import encryption_manager

def create_test_elderly_user():
    with app.app_context():
        # Create a test elderly user directly
        test_user = User(
            nric="T1234567Z",  # This will be encrypted
            full_name="Test Elder",
            language_preference="english",
            event_interests="social,recreational",
            user_type="elderly",
            password_hash=generate_password_hash("password123"),
            security_q1="first_pet",
            security_q2="favorite_food", 
            security_q3="favorite_color",
            two_factor_enabled=True,
            is_active=True
        )
        
        # Set security answers
        test_user.set_security_answers("dog", "rice", "blue")
        
        # Encrypt sensitive data
        test_user.encrypt_sensitive_data()
        
        try:
            db.session.add(test_user)
            db.session.commit()
            print(f"Created test user with ID: {test_user.id}")
            print(f"NRIC (encrypted): {test_user.nric}")
            
            # Test decryption
            decrypted_nric = encryption_manager.decrypt_data(test_user.nric)
            print(f"NRIC (decrypted): {decrypted_nric}")
            
            # Test login query
            found_user = User.safe_query_by_nric("T1234567Z")
            if found_user:
                print(f"Login query successful: Found user {found_user.id}")
                print(f"Password check: {found_user.check_password('password123')}")
            else:
                print("Login query failed - user not found")
                
        except Exception as e:
            print(f"Error: {e}")
            db.session.rollback()

if __name__ == "__main__":
    create_test_elderly_user()