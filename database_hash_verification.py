"""
Database Hash Verification Script
Verifies that security answers are properly hashed in the database
"""

import os
import sys
sys.path.append('.')

from app import app, db
from models import User
from werkzeug.security import check_password_hash

def verify_database_hashing():
    """Check if security answers in database are properly hashed"""
    print("🔍 Verifying Security Answer Hashing in Database")
    print("=" * 55)
    
    with app.app_context():
        try:
            # Get all elderly users
            elderly_users = User.query.filter_by(user_type='elderly').all()
            
            if not elderly_users:
                print("ℹ️  No elderly users found in database")
                return
            
            for user in elderly_users:
                print(f"\n👤 User: {user.full_name or 'Unknown'} (ID: {user.id})")
                
                # Check each security answer
                answers = [
                    ('Answer 1', user.security_a1),
                    ('Answer 2', user.security_a2), 
                    ('Answer 3', user.security_a3)
                ]
                
                for label, answer in answers:
                    if answer:
                        # Check if it looks like a hash (starts with pbkdf2 or scrypt)
                        is_hashed = (answer.startswith('pbkdf2:') or 
                                   answer.startswith('scrypt:') or
                                   len(answer) > 50)  # Hashes are typically long
                        
                        if is_hashed:
                            print(f"  ✅ {label}: Properly hashed ({answer[:20]}...)")
                        else:
                            print(f"  ❌ {label}: NOT HASHED - Plaintext detected: {answer}")
                    else:
                        print(f"  ⚪ {label}: Empty")
            
            print(f"\n📊 Total elderly users checked: {len(elderly_users)}")
            
        except Exception as e:
            print(f"❌ Database verification error: {e}")

def update_existing_unhashed_answers():
    """Update any existing unhashed security answers"""
    print("\n🔄 Updating Any Unhashed Security Answers")
    print("-" * 40)
    
    with app.app_context():
        try:
            elderly_users = User.query.filter_by(user_type='elderly').all()
            updated_count = 0
            
            for user in elderly_users:
                needs_update = False
                
                # Check if answers need hashing
                answers_to_hash = []
                if user.security_a1 and not (user.security_a1.startswith('pbkdf2:') or user.security_a1.startswith('scrypt:')):
                    answers_to_hash.append(('a1', user.security_a1))
                    needs_update = True
                
                if user.security_a2 and not (user.security_a2.startswith('pbkdf2:') or user.security_a2.startswith('scrypt:')):
                    answers_to_hash.append(('a2', user.security_a2))
                    needs_update = True
                
                if user.security_a3 and not (user.security_a3.startswith('pbkdf2:') or user.security_a3.startswith('scrypt:')):
                    answers_to_hash.append(('a3', user.security_a3))
                    needs_update = True
                
                if needs_update:
                    print(f"🔄 Updating user {user.full_name} (ID: {user.id})")
                    
                    # Re-hash the answers using the model method
                    original_answers = {}
                    for field, answer in answers_to_hash:
                        original_answers[field] = answer
                    
                    # Use the set_security_answers method to properly hash them
                    user.set_security_answers(
                        original_answers.get('a1'),
                        original_answers.get('a2'), 
                        original_answers.get('a3')
                    )
                    
                    updated_count += 1
            
            if updated_count > 0:
                db.session.commit()
                print(f"✅ Updated {updated_count} users with properly hashed security answers")
            else:
                print("✅ All security answers are already properly hashed")
                
        except Exception as e:
            print(f"❌ Update error: {e}")
            db.session.rollback()

if __name__ == "__main__":
    verify_database_hashing()
    update_existing_unhashed_answers()
    print("\n🔐 Database hash verification complete!")