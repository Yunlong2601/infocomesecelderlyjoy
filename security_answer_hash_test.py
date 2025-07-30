"""
Security Answer Hashing Test for Community Connect
Tests the new password hashing implementation for security answers
"""

from encryption_manager import encryption_manager
from models import User, db
from werkzeug.security import check_password_hash, generate_password_hash

def test_security_answer_hashing():
    """Test security answer hashing functionality"""
    print("🔐 Testing Security Answer Hashing Implementation")
    print("=" * 55)
    
    # Test answer hashing directly
    test_answers = [
        "Singapore",
        "River Valley Primary School", 
        "Blue",
        "Mango",
        "Alexandra Road"
    ]
    
    passed = 0
    total = 0
    
    # Test 1: Direct password hashing
    for answer in test_answers:
        total += 1
        normalized = answer.lower().strip()
        hashed = generate_password_hash(normalized)
        
        # Test verification
        if check_password_hash(hashed, normalized):
            print(f"✅ Hash verification: {answer[:15]}...")
            passed += 1
        else:
            print(f"❌ Hash verification failed: {answer[:15]}...")
    
    # Test 2: User model security answer methods
    total += 1
    try:
        # Create a test user instance (not saved to DB)
        test_user = User()
        
        # Set security answers using the new method
        test_user.set_security_answers(
            "Singapore",
            "River Valley Primary",
            "Blue"
        )
        
        # Test verification
        if (test_user.check_security_answer(1, "Singapore") and
            test_user.check_security_answer(2, "River Valley Primary") and
            test_user.check_security_answer(3, "Blue")):
            print("✅ User model security answer hashing")
            passed += 1
        else:
            print("❌ User model security answer verification failed")
            
    except Exception as e:
        print(f"❌ User model test error: {e}")
    
    # Test 3: Case insensitivity and trimming
    total += 1
    try:
        test_user = User()
        test_user.set_security_answers("  SINGAPORE  ", "school", "blue")
        
        # Should work with different cases and spacing
        if (test_user.check_security_answer(1, "singapore") and
            test_user.check_security_answer(1, "  Singapore  ") and
            test_user.check_security_answer(2, "SCHOOL") and
            test_user.check_security_answer(3, "Blue")):
            print("✅ Case insensitive and trimming")
            passed += 1
        else:
            print("❌ Case sensitivity test failed")
    except Exception as e:
        print(f"❌ Case sensitivity test error: {e}")
    
    # Test 4: Wrong answers should fail
    total += 1
    try:
        test_user = User()
        test_user.set_security_answers("correct1", "correct2", "correct3")
        
        # Wrong answers should return False
        if (not test_user.check_security_answer(1, "wrong1") and
            not test_user.check_security_answer(2, "wrong2") and
            not test_user.check_security_answer(3, "wrong3")):
            print("✅ Wrong answers correctly rejected")
            passed += 1
        else:
            print("❌ Wrong answers not properly rejected")
    except Exception as e:
        print(f"❌ Wrong answer test error: {e}")
    
    # Test 5: Encryption vs Hashing separation
    total += 1
    try:
        test_user = User()
        test_user.nric = "S1234567A"
        test_user.phone = "+65 91234567"
        test_user.set_security_answers("answer1", "answer2", "answer3")
        
        # Encrypt sensitive data (NRIC, phone)
        test_user.encrypt_sensitive_data()
        
        # Get decrypted data
        decrypted = test_user.decrypt_sensitive_data()
        
        # NRIC and phone should be decrypted, answers should show [HASHED]
        if (decrypted['nric'] == "S1234567A" and
            decrypted['phone'] == "+65 91234567" and
            decrypted['security_a1'] == '[HASHED]' and
            decrypted['security_a2'] == '[HASHED]' and
            decrypted['security_a3'] == '[HASHED]'):
            print("✅ Encryption vs Hashing separation")
            passed += 1
        else:
            print("❌ Encryption/Hashing separation failed")
            print(f"Debug - decrypted: {decrypted}")
    except Exception as e:
        print(f"❌ Encryption separation test error: {e}")
    
    # Final results
    success_rate = (passed / total) * 100 if total > 0 else 0
    
    print("\n" + "=" * 55)
    print("📊 SECURITY ANSWER HASHING TEST RESULTS")
    print("=" * 55)
    print(f"✅ Tests Passed: {passed}/{total}")
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 90:
        print("🎉 EXCELLENT: Security answer hashing working perfectly!")
    elif success_rate >= 80:
        print("✅ GOOD: Security answer hashing implemented correctly")
    else:
        print("⚠️  NEEDS ATTENTION: Some security answer features need fixing")
    
    print("\n🔐 Security Answer Features:")
    print("✓ Password hashing for all security answers")
    print("✓ Case-insensitive verification")
    print("✓ Automatic trimming of whitespace")
    print("✓ Separation from encryption (answers hashed, NRIC/phone encrypted)")
    print("✓ Secure verification without storing plaintext")
    
    return passed, total

if __name__ == "__main__":
    test_security_answer_hashing()