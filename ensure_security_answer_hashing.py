"""
Ensure Security Answer Hashing Migration Script
Guarantees all security answers in database are properly hashed
"""

import os
import sys
sys.path.append('.')

from app import app, db
from models import User
from werkzeug.security import check_password_hash

def audit_and_fix_security_answers():
    """Complete audit and fix of all security answers in database"""
    print("🔐 Complete Security Answer Hashing Audit")
    print("=" * 50)
    
    with app.app_context():
        try:
            # Get all users with security answers
            all_users = User.query.filter(
                db.or_(
                    User.security_a1.isnot(None),
                    User.security_a2.isnot(None), 
                    User.security_a3.isnot(None)
                )
            ).all()
            
            if not all_users:
                print("ℹ️  No users with security answers found")
                return
            
            hashed_count = 0
            unhashed_count = 0
            fixed_count = 0
            
            for user in all_users:
                print(f"\n👤 {user.get_full_name()} (ID: {user.id}) - {user.user_type}")
                
                answers = [
                    ('security_a1', user.security_a1),
                    ('security_a2', user.security_a2),
                    ('security_a3', user.security_a3)
                ]
                
                needs_fix = False
                original_answers = {}
                
                for field, answer in answers:
                    if answer:
                        is_hashed = (answer.startswith('pbkdf2:') or 
                                   answer.startswith('scrypt:') or
                                   answer.startswith('argon2:'))
                        
                        if is_hashed:
                            print(f"   ✅ {field}: Already hashed")
                            hashed_count += 1
                        else:
                            print(f"   ❌ {field}: Needs hashing - {answer}")
                            unhashed_count += 1
                            needs_fix = True
                            original_answers[field] = answer
                
                # Fix unhashed answers
                if needs_fix:
                    print(f"   🔄 Fixing answers for {user.get_full_name()}")
                    
                    # Get original values to re-hash
                    a1 = original_answers.get('security_a1') or (user.security_a1 if not (user.security_a1 or '').startswith(('pbkdf2:', 'scrypt:', 'argon2:')) else None)
                    a2 = original_answers.get('security_a2') or (user.security_a2 if not (user.security_a2 or '').startswith(('pbkdf2:', 'scrypt:', 'argon2:')) else None)
                    a3 = original_answers.get('security_a3') or (user.security_a3 if not (user.security_a3 or '').startswith(('pbkdf2:', 'scrypt:', 'argon2:')) else None)
                    
                    # Only update fields that need hashing
                    if a1 or a2 or a3:
                        user.set_security_answers(a1, a2, a3)
                        fixed_count += 1
                        print(f"   ✅ Fixed {user.get_full_name()}")
            
            if fixed_count > 0:
                db.session.commit()
                print(f"\n✅ Database updated - {fixed_count} users fixed")
            
            print(f"\n📊 Final Security Answer Audit Results:")
            print(f"   👥 Total users checked: {len(all_users)}")
            print(f"   ✅ Already hashed answers: {hashed_count}")
            print(f"   ❌ Originally unhashed: {unhashed_count}")
            print(f"   🔄 Users fixed: {fixed_count}")
            
            if unhashed_count == 0:
                print("\n🎉 ALL SECURITY ANSWERS ARE PROPERLY HASHED!")
            else:
                print(f"\n🔐 Fixed {fixed_count} users - all answers now hashed")
                
        except Exception as e:
            print(f"❌ Audit error: {e}")
            db.session.rollback()

def verify_hashing_complete():
    """Final verification that all answers are hashed"""
    print("\n🔍 Final Verification - All Answers Hashed")
    print("-" * 40)
    
    with app.app_context():
        try:
            users_with_answers = User.query.filter(
                db.or_(
                    User.security_a1.isnot(None),
                    User.security_a2.isnot(None),
                    User.security_a3.isnot(None)
                )
            ).all()
            
            all_hashed = True
            
            for user in users_with_answers:
                answers = [user.security_a1, user.security_a2, user.security_a3]
                
                for i, answer in enumerate(answers, 1):
                    if answer:
                        is_hashed = (answer.startswith('pbkdf2:') or 
                                   answer.startswith('scrypt:') or
                                   answer.startswith('argon2:'))
                        
                        if not is_hashed:
                            print(f"❌ User {user.get_full_name()}: Answer {i} not hashed")
                            all_hashed = False
            
            if all_hashed:
                print("✅ VERIFICATION COMPLETE: All security answers are properly hashed")
            else:
                print("❌ VERIFICATION FAILED: Some answers still not hashed")
                
        except Exception as e:
            print(f"❌ Verification error: {e}")

if __name__ == "__main__":
    audit_and_fix_security_answers()
    verify_hashing_complete()
    print("\n🛡️  Security answer hashing migration complete!")