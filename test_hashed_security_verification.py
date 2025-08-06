"""
Test the hashed security answers work correctly for existing users
"""

import os
import sys
sys.path.append('.')

from app import app, db
from models import User

def test_existing_user_verification():
    """Test that existing user can verify with hashed answers"""
    print("🧪 Testing Hashed Security Answer Verification")
    print("=" * 50)
    
    with app.app_context():
        try:
            # Get the existing user
            user = User.query.filter_by(user_type='elderly').first()
            
            if not user:
                print("❌ No elderly user found for testing")
                return
            
            print(f"👤 Testing user: {user.full_name}")
            
            # Test the original answers (should work)
            test_cases = [
                (1, "singapore", "Should work - original answer"),
                (2, "jay", "Should work - original answer"), 
                (3, "singapore", "Should work - original answer"),
                (1, "SINGAPORE", "Should work - case insensitive"),
                (2, "  jay  ", "Should work - with spaces"),
                (1, "malaysia", "Should fail - wrong answer"),
                (2, "john", "Should fail - wrong answer")
            ]
            
            passed = 0
            total = len(test_cases)
            
            for question_num, answer, description in test_cases:
                result = user.check_security_answer(question_num, answer)
                expected = "Should work" in description
                
                if result == expected:
                    status = "✅" if expected else "✅"
                    print(f"  {status} Q{question_num}: '{answer}' - {description}")
                    passed += 1
                else:
                    status = "❌"
                    print(f"  {status} Q{question_num}: '{answer}' - {description} (Expected: {expected}, Got: {result})")
            
            print(f"\n📊 Verification Test Results: {passed}/{total} passed")
            
            if passed == total:
                print("🎉 All security answer verifications working correctly!")
            else:
                print("⚠️  Some verification tests failed - needs investigation")
                
        except Exception as e:
            print(f"❌ Test error: {e}")

if __name__ == "__main__":
    test_existing_user_verification()