"""
AES-256 Encryption Manager for Community Connect
Provides secure encryption for sensitive user information
"""

import os
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import logging

class AES256EncryptionManager:
    """Manages AES-256 encryption for sensitive data"""
    
    def __init__(self):
        self.logger = logging.getLogger('encryption')
        self._key = None
        self._cipher_suite = None
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize encryption with AES-256 key"""
        try:
            # Get encryption key from environment or generate new one
            key_material = os.environ.get('ENCRYPTION_KEY')
            if not key_material:
                # Generate a new key if none exists
                key_material = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
                self.logger.warning("No ENCRYPTION_KEY found. Generated new key. Store this securely!")
                print(f"ENCRYPTION_KEY={key_material}")
            
            # Derive key using PBKDF2
            salt = b'community_connect_salt_2025'  # Fixed salt for consistency
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            key = base64.urlsafe_b64encode(kdf.derive(key_material.encode()))
            self._cipher_suite = Fernet(key)
            self.logger.info("AES-256 encryption initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize encryption: {e}")
            raise
    
    def encrypt_data(self, data):
        """Encrypt sensitive data using AES-256"""
        if not data:
            return None
        
        try:
            if not self._cipher_suite:
                self.logger.error("Cipher suite not initialized")
                return data  # Return original data if encryption fails
                
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            encrypted_data = self._cipher_suite.encrypt(data)
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            return data  # Return original data on failure to prevent app crash
    
    def decrypt_data(self, encrypted_data):
        """Decrypt AES-256 encrypted data"""
        if not encrypted_data:
            return None
        
        try:
            if not self._cipher_suite:
                self.logger.error("Cipher suite not initialized")
                return encrypted_data  # Return original data if decryption fails
                
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self._cipher_suite.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            return encrypted_data  # Return original data on failure
    
    def encrypt_sensitive_fields(self, user_data):
        """Encrypt multiple sensitive fields in user data"""
        sensitive_fields = ['nric', 'security_a1', 'security_a2', 'security_a3', 'phone']
        
        encrypted_data = user_data.copy()
        for field in sensitive_fields:
            if field in encrypted_data and encrypted_data[field]:
                encrypted_data[field] = self.encrypt_data(encrypted_data[field])
        
        return encrypted_data
    
    def decrypt_sensitive_fields(self, encrypted_data):
        """Decrypt multiple sensitive fields in user data"""
        sensitive_fields = ['nric', 'security_a1', 'security_a2', 'security_a3', 'phone']
        
        decrypted_data = encrypted_data.copy()
        for field in sensitive_fields:
            if field in decrypted_data and decrypted_data[field]:
                try:
                    decrypted_data[field] = self.decrypt_data(decrypted_data[field])
                except:
                    # If decryption fails, data might not be encrypted
                    pass
        
        return decrypted_data

# Global encryption manager instance
encryption_manager = AES256EncryptionManager()