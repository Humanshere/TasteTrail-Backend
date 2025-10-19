"""
Custom JWT Authentication
Extends Django REST Framework SimpleJWT authentication
"""

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken


class CustomJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication that extracts user info from token claims.
    Creates a lightweight user object from token payload.
    """
    
    def get_user(self, validated_token):
        """
        Extract user information from the validated token.
        
        Args:
            validated_token: Validated JWT token
            
        Returns:
            AuthenticatedUser object with user information
            
        Raises:
            InvalidToken: If token doesn't contain valid user data
        """
        try:
            user_id = validated_token.get('user_id')
            email = validated_token.get('email')
            role = validated_token.get('role')
            username = validated_token.get('username', '')
            
            if not user_id:
                raise InvalidToken('Token contains no valid user identification')
            
            # Create a lightweight user object
            return AuthenticatedUser(
                user_id=user_id,
                email=email,
                role=role,
                username=username
            )
            
        except KeyError as e:
            raise InvalidToken(f'Token missing required field: {e}')


class AuthenticatedUser:
    """Lightweight user object created from JWT token."""
    
    def __init__(self, user_id: str, email: str, role: str, username: str = ''):
        self.id = user_id
        self.pk = user_id  # Django compatibility
        self.email = email
        self.role = role
        self.username = username
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
    
    def is_admin(self) -> bool:
        return self.role == 'admin'