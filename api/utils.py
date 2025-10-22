"""
Utility Functions
Provides helper functions for password hashing, token generation, etc.
"""

import os
import bcrypt
import secrets
from typing import Dict, Any
from datetime import datetime, timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from dotenv import load_dotenv

load_dotenv()


class PasswordHasher:
    """Handles password hashing and verification using bcrypt."""
    
    # Get bcrypt rounds from environment or use default
    BCRYPT_ROUNDS = int(os.getenv('BCRYPT_ROUNDS', 12))
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password as string
        """
        salt = bcrypt.gensalt(rounds=cls.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @classmethod
    def verify_password(cls, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password to verify
            hashed_password: Hashed password to compare against
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except Exception:
            return False


class TokenGenerator:
    """Generates secure tokens for various purposes."""
    
    @staticmethod
    def generate_reset_token(length: int = 32) -> str:
        """
        Generate a secure password reset token.
        
        Args:
            length: Length of the token (default: 32)
            
        Returns:
            Secure random token
        """
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_numeric_code(digits: int = 6) -> str:
        """Generate a numeric verification code with given number of digits."""
        # Use secrets for cryptographically strong randomness
        upper = 10 ** digits
        num = secrets.randbelow(upper)
        return str(num).zfill(digits)
    
    @staticmethod
    def generate_jwt_tokens(user_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate JWT access and refresh tokens.
        
        Args:
            user_data: Dictionary containing user information
                      Must include: id, email, role
            
        Returns:
            Dictionary with 'access' and 'refresh' tokens
        """
        # Create a mock user object for SimpleJWT
        class MockUser:
            def __init__(self, user_id):
                self.pk = user_id
                self.id = user_id
        
        mock_user = MockUser(user_data['id'])
        refresh = RefreshToken.for_user(mock_user)
        
        # Add custom claims to the token payload
        refresh['email'] = user_data['email']
        refresh['role'] = user_data['role']
        refresh['username'] = user_data.get('username', '')
        
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }


class DateTimeHelper:
    """Helper functions for datetime operations."""
    
    @staticmethod
    def get_utc_now() -> datetime:
        """Get current UTC datetime."""
        return datetime.utcnow()
    
    @staticmethod
    def get_password_reset_expiry() -> datetime:
        """
        Get expiration datetime for password reset token.
        
        Returns:
            Datetime object representing token expiration
        """
        expiry_minutes = int(
            os.getenv('PASSWORD_RESET_TOKEN_EXPIRY_MINUTES', 15)
        )
        return datetime.utcnow() + timedelta(minutes=expiry_minutes)

    @staticmethod
    def get_email_verification_expiry() -> datetime:
        """Get expiration datetime for email verification token/code."""
        minutes = int(os.getenv('EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES', 30))
        return datetime.utcnow() + timedelta(minutes=minutes)
    
    @staticmethod
    def is_expired(expiry_datetime: datetime) -> bool:
        """Check if a datetime has expired."""
        return datetime.utcnow() > expiry_datetime


class ResponseHelper:
    """Helper functions for creating standardized API responses."""
    
    @staticmethod
    def success_response(message: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a success response."""
        response = {
            'success': True,
            'message': message
        }
        if data:
            response['data'] = data
        return response
    
    @staticmethod
    def error_response(error: str, details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create an error response."""
        response = {
            'success': False,
            'error': error
        }
        if details:
            response['details'] = details
        return response