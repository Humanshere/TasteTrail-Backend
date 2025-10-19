"""
Input Validators
Validates user inputs like email, password, username, etc.
"""

import re
from typing import Tuple, Optional


class EmailValidator:
    """Validates email format and structure."""
    
    # Email regex pattern (RFC 5322 compliant)
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    @classmethod
    def validate(cls, email: str) -> Tuple[bool, Optional[str]]:
        """
        Validate email format.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email or not email.strip():
            return False, "Email is required"
        
        email = email.strip().lower()
        
        if len(email) > 254:  # RFC 5321
            return False, "Email address is too long"
        
        if not cls.EMAIL_PATTERN.match(email):
            return False, "Invalid email format"
        
        return True, None


class PasswordValidator:
    """Validates password strength and requirements."""
    
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    
    @classmethod
    def validate(cls, password: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password strength.
        
        Requirements:
        - At least 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not password:
            return False, "Password is required"
        
        if len(password) < cls.MIN_LENGTH:
            return False, f"Password must be at least {cls.MIN_LENGTH} characters long"
        
        if len(password) > cls.MAX_LENGTH:
            return False, f"Password must not exceed {cls.MAX_LENGTH} characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', password):
            return False, "Password must contain at least one special character"
        
        return True, None


class UsernameValidator:
    """Validates username format and requirements."""
    
    MIN_LENGTH = 3
    MAX_LENGTH = 30
    
    # Username pattern: alphanumeric, underscore, hyphen
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    @classmethod
    def validate(cls, username: str) -> Tuple[bool, Optional[str]]:
        """
        Validate username.
        
        Requirements:
        - 3-30 characters
        - Only letters, numbers, underscore, and hyphen
        - Cannot start or end with special characters
        
        Args:
            username: Username to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not username or not username.strip():
            return False, "Username is required"
        
        username = username.strip()
        
        if len(username) < cls.MIN_LENGTH:
            return False, f"Username must be at least {cls.MIN_LENGTH} characters"
        
        if len(username) > cls.MAX_LENGTH:
            return False, f"Username must not exceed {cls.MAX_LENGTH} characters"
        
        if not cls.USERNAME_PATTERN.match(username):
            return False, "Username can only contain letters, numbers, underscore, and hyphen"
        
        if username[0] in ['-', '_'] or username[-1] in ['-', '_']:
            return False, "Username cannot start or end with special characters"
        
        return True, None


class RoleValidator:
    """Validates user role."""
    
    VALID_ROLES = ['user', 'admin']
    
    @classmethod
    def validate(cls, role: str) -> Tuple[bool, Optional[str]]:
        """Validate user role."""
        if not role:
            return True, None  # Role is optional, defaults to 'user'
        
        role = role.lower().strip()
        
        if role not in cls.VALID_ROLES:
            return False, f"Role must be one of: {', '.join(cls.VALID_ROLES)}"
        
        return True, None