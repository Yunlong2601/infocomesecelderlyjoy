#!/usr/bin/env python3
"""Debug script to test login functionality"""

from app import app, db
from models import User
from encryption_manager import encryption_manager
import re

def test_login_debug():
    with app.app_context():
        print("=== LOGIN DEBUG SCRIPT ===")
        
        # Test NRIC that was used: Q1234567W
        test_nric = "Q1234567W"
        print(f"Testing login for NRIC: {test_nric}")
        
        # Get all elderly users
        elderly_users = User.query.filter_by(user_type='elderly').all()
        print(f"Found {len(elderly_users)} elderly users")
        
        for user in elderly_users:
            print(f"\nUser ID: {user.id}")
            print(f"Full name: {user.full_name}")
            print(f"NRIC (encrypted): {user.nric[:50] if user.nric else 'None'}...")
            
            if user.nric:
                try:
                    decrypted_nric = encryption_manager.decrypt_data(user.nric)
                    print(f"NRIC (decrypted): {decrypted_nric}")
                    nric_pattern = r'^[STFG]\d{7}[A-Z]$'
                    print(f"Valid NRIC format: {bool(re.match(nric_pattern, decrypted_nric))}")
                    
                    if decrypted_nric == test_nric:
                        print("*** MATCH FOUND! ***")
                        print(f"Password hash: {user.password_hash[:30]}...")
                        return user
                    else:
                        print(f"No match: '{decrypted_nric}' != '{test_nric}'")
                        
                except Exception as e:
                    print(f"Decryption failed: {e}")
                    # Try unencrypted match
                    if user.nric == test_nric:
                        print("*** UNENCRYPTED MATCH FOUND! ***")
                        return user
        
        print("\n=== TESTING safe_query_by_nric METHOD ===")
        result = User.safe_query_by_nric(test_nric)
        if result:
            print(f"Method found user: {result.id} - {result.full_name}")
        else:
            print("Method returned None")
        
        return None

if __name__ == "__main__":
    test_login_debug()