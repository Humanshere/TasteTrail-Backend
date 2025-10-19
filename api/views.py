"""
API Views
Handles all API endpoints for user management
"""

import logging
from datetime import datetime
from typing import Dict, Any
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from pymongo.errors import DuplicateKeyError
from bson import ObjectId

from .mongo_db import users_collection, password_resets_collection
from .validators import (
    EmailValidator, PasswordValidator, 
    UsernameValidator, RoleValidator
)
from .utils import (
    PasswordHasher, TokenGenerator, 
    DateTimeHelper, ResponseHelper
)
from .serializers import UserSerializer, TokenSerializer

logger = logging.getLogger(__name__)


class RegisterView(APIView):
    """
    User Registration Endpoint
    
    POST /api/register/
    Body: {
        "email": "user@example.com",
        "username": "username",
        "password": "SecurePassword123!",
        "role": "user"  # Optional, defaults to "user"
    }
    """
    permission_classes = [AllowAny]
    def post(self, request):
        """Handle user registration."""
        try:
            # Extract and clean input data
            email = request.data.get('email', '').strip().lower()
            username = request.data.get('username', '').strip()
            password = request.data.get('password', '')
            role = request.data.get('role', 'user').strip().lower()
            
            # Validate email
            is_valid, error = EmailValidator.validate(email)
            if not is_valid:
                return Response(
                    ResponseHelper.error_response(error),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate username
            is_valid, error = UsernameValidator.validate(username)
            if not is_valid:
                return Response(
                    ResponseHelper.error_response(error),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate password
            is_valid, error = PasswordValidator.validate(password)
            if not is_valid:
                return Response(
                    ResponseHelper.error_response(error),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate role
            is_valid, error = RoleValidator.validate(role)
            if not is_valid:
                return Response(
                    ResponseHelper.error_response(error),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Hash password
            hashed_password = PasswordHasher.hash_password(password)
            
            # Create user document
            user_doc = {
                'email': email,
                'username': username,
                'password': hashed_password,
                'role': role or 'user',
                'is_active': True,
                'created_at': DateTimeHelper.get_utc_now(),
                'updated_at': DateTimeHelper.get_utc_now(),
                'last_login': None
            }
            
            # Insert into database
            result = users_collection.insert_one(user_doc)
            user_doc['_id'] = result.inserted_id
            
            # Serialize and return user data
            user_data = UserSerializer.serialize_user(user_doc)
            
            logger.info(f"New user registered: {email}")
            
            return Response(
                ResponseHelper.success_response(
                    'User registered successfully',
                    {'user': user_data}
                ),
                status=status.HTTP_201_CREATED
            )
            
        except DuplicateKeyError:
            return Response(
                ResponseHelper.error_response(
                    'A user with this email or username already exists'
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Registration error: {e}", exc_info=True)
            return Response(
                ResponseHelper.error_response(
                    'An error occurred during registration'
                ),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginView(APIView):
    """
    User Login Endpoint
    
    POST /api/login/
    Body: {
        "email": "user@example.com",
        "password": "SecurePassword123!"
    }
    """
    permission_classes = [AllowAny]
    def post(self, request):
        """Handle user login and JWT token generation."""
        try:
            # Extract and clean input data
            email = request.data.get('email', '').strip().lower()
            password = request.data.get('password', '')
            
            # Validate required fields
            if not email or not password:
                return Response(
                    ResponseHelper.error_response(
                        'Email and password are required'
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Find user by email
            user = users_collection.find_one({'email': email})
            
            if not user:
                return Response(
                    ResponseHelper.error_response(
                        'Invalid email or password'
                    ),
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Check if account is active
            if not user.get('is_active', True):
                return Response(
                    ResponseHelper.error_response(
                        'Account is deactivated. Please contact support'
                    ),
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Verify password
            if not PasswordHasher.verify_password(password, user['password']):
                return Response(
                    ResponseHelper.error_response(
                        'Invalid email or password'
                    ),
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Prepare user data for token
            user_data = {
                'id': str(user['_id']),
                'email': user['email'],
                'username': user['username'],
                'role': user['role']
            }
            
            # Generate JWT tokens
            tokens = TokenGenerator.generate_jwt_tokens(user_data)
            
            # Update last login timestamp
            users_collection.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'last_login': DateTimeHelper.get_utc_now()
                    }
                }
            )
            
            # Serialize response
            user_serialized = UserSerializer.serialize_user(user)
            token_response = TokenSerializer.serialize_tokens(tokens, user_serialized)
            
            logger.info(f"User logged in: {email}")
            
            return Response(
                ResponseHelper.success_response(
                    'Login successful',
                    token_response
                ),
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Login error: {e}", exc_info=True)
            return Response(
                ResponseHelper.error_response(
                    'An error occurred during login'
                ),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RequestPasswordResetView(APIView):
    """
    Request Password Reset Endpoint
    
    POST /api/password-reset/request/
    Body: {
        "email": "user@example.com"
    }
    """
    
    def post(self, request):
        """Generate and send password reset token."""
        try:
            email = request.data.get('email', '').strip().lower()
            
            if not email:
                return Response(
                    ResponseHelper.error_response('Email is required'),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate email format
            is_valid, error = EmailValidator.validate(email)
            if not is_valid:
                return Response(
                    ResponseHelper.error_response(error),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Find user
            user = users_collection.find_one({'email': email})
            
            # Generic response to prevent user enumeration
            response_message = (
                'If an account with this email exists, '
                'a password reset link has been sent'
            )
            
            if user:
                # Generate secure token
                token = TokenGenerator.generate_reset_token()
                expiration = DateTimeHelper.get_password_reset_expiry()
                
                # Delete any existing reset tokens for this email
                password_resets_collection.delete_many({'email': email})
                
                # Store new reset token
                password_resets_collection.insert_one({
                    'email': email,
                    'token': token,
                    'created_at': DateTimeHelper.get_utc_now(),
                    'expires_at': expiration,
                    'used': False
                })
                
                logger.info(f"Password reset requested for: {email}")
                
                # In production, send email here
                # send_password_reset_email(email, token)
                
                # For development, include token in response
                return Response(
                    ResponseHelper.success_response(
                        response_message,
                        {
                            'token': token,  # Remove in production
                            'expires_in_minutes': 15
                        }
                    ),
                    status=status.HTTP_200_OK
                )
            
            return Response(
                ResponseHelper.success_response(response_message),
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Password reset request error: {e}", exc_info=True)
            return Response(
                ResponseHelper.error_response(
                    'An error occurred processing your request'
                ),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ConfirmPasswordResetView(APIView):
    """
    Confirm Password Reset Endpoint
    
    POST /api/password-reset/confirm/
    Body: {
        "token": "reset_token_here",
        "new_password": "NewSecurePassword123!"
    }
    """
    
    def post(self, request):
        """Confirm password reset with token and set new password."""
        try:
            token = request.data.get('token', '').strip()
            new_password = request.data.get('new_password', '')
            
            # Validate required fields
            if not token or not new_password:
                return Response(
                    ResponseHelper.error_response(
                        'Token and new password are required'
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate new password strength
            is_valid, error = PasswordValidator.validate(new_password)
            if not is_valid:
                return Response(
                    ResponseHelper.error_response(error),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Find reset token
            reset_request = password_resets_collection.find_one({
                'token': token,
                'used': False
            })
            
            if not reset_request:
                return Response(
                    ResponseHelper.error_response(
                        'Invalid or already used token'
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if token has expired
            if DateTimeHelper.is_expired(reset_request['expires_at']):
                password_resets_collection.delete_one({'token': token})
                return Response(
                    ResponseHelper.error_response(
                        'Token has expired. Please request a new one'
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Hash new password
            hashed_password = PasswordHasher.hash_password(new_password)
            
            # Update user's password
            update_result = users_collection.update_one(
                {'email': reset_request['email']},
                {
                    '$set': {
                        'password': hashed_password,
                        'updated_at': DateTimeHelper.get_utc_now()
                    }
                }
            )
            
            if update_result.matched_count == 0:
                return Response(
                    ResponseHelper.error_response('User not found'),
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Mark token as used
            password_resets_collection.update_one(
                {'token': token},
                {'$set': {'used': True}}
            )
            
            logger.info(f"Password reset completed for: {reset_request['email']}")
            
            return Response(
                ResponseHelper.success_response(
                    'Password has been reset successfully'
                ),
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Password reset confirmation error: {e}", exc_info=True)
            return Response(
                ResponseHelper.error_response(
                    'An error occurred resetting your password'
                ),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ProfileView(APIView):
    """
    User Profile Management Endpoint
    Requires JWT authentication
    
    GET /api/profile/
    Headers: Authorization: Bearer <access_token>
    
    PUT /api/profile/
    Headers: Authorization: Bearer <access_token>
    Body: {
        "username": "new_username"
    }
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Retrieve authenticated user's profile."""
        try:
            user_id = request.user.id
            user = users_collection.find_one({'_id': ObjectId(user_id)})
            
            if not user:
                return Response(
                    ResponseHelper.error_response('User not found'),
                    status=status.HTTP_404_NOT_FOUND
                )
            
            user_data = UserSerializer.serialize_user(user)
            
            return Response(
                ResponseHelper.success_response(
                    'Profile retrieved successfully',
                    {'user': user_data}
                ),
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Profile retrieval error: {e}", exc_info=True)
            return Response(
                ResponseHelper.error_response(
                    'An error occurred retrieving your profile'
                ),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def put(self, request):
        """Update authenticated user's profile."""
        try:
            user_id = request.user.id
            new_username = request.data.get('username', '').strip()
            
            # Validate username
            is_valid, error = UsernameValidator.validate(new_username)
            if not is_valid:
                return Response(
                    ResponseHelper.error_response(error),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if username is already taken by another user
            existing_user = users_collection.find_one({'username': new_username})
            if existing_user and str(existing_user['_id']) != user_id:
                return Response(
                    ResponseHelper.error_response(
                        'This username is already taken'
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Update user's profile
            update_result = users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {
                    '$set': {
                        'username': new_username,
                        'updated_at': DateTimeHelper.get_utc_now()
                    }
                }
            )
            
            if update_result.matched_count == 0:
                return Response(
                    ResponseHelper.error_response('User not found'),
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Fetch and return updated profile
            updated_user = users_collection.find_one({'_id': ObjectId(user_id)})
            user_data = UserSerializer.serialize_user(updated_user)
            
            logger.info(f"Profile updated for user: {user_id}")
            
            return Response(
                ResponseHelper.success_response(
                    'Profile updated successfully',
                    {'user': user_data}
                ),
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Profile update error: {e}", exc_info=True)
            return Response(
                ResponseHelper.error_response(
                    'An error occurred updating your profile'
                ),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ChangePasswordView(APIView):
    """
    Change Password Endpoint (for authenticated users)
    
    POST /api/change-password/
    Headers: Authorization: Bearer <access_token>
    Body: {
        "current_password": "CurrentPassword123!",
        "new_password": "NewPassword123!"
    }
    """
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Change authenticated user's password."""
        try:
            user_id = request.user.id
            current_password = request.data.get('current_password', '')
            new_password = request.data.get('new_password', '')
            
            # Validate required fields
            if not current_password or not new_password:
                return Response(
                    ResponseHelper.error_response(
                        'Current password and new password are required'
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate new password strength
            is_valid, error = PasswordValidator.validate(new_password)
            if not is_valid:
                return Response(
                    ResponseHelper.error_response(error),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Find user
            user = users_collection.find_one({'_id': ObjectId(user_id)})
            
            if not user:
                return Response(
                    ResponseHelper.error_response('User not found'),
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Verify current password
            if not PasswordHasher.verify_password(current_password, user['password']):
                return Response(
                    ResponseHelper.error_response(
                        'Current password is incorrect'
                    ),
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Check if new password is same as current
            if current_password == new_password:
                return Response(
                    ResponseHelper.error_response(
                        'New password must be different from current password'
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Hash new password
            hashed_password = PasswordHasher.hash_password(new_password)
            
            # Update password
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {
                    '$set': {
                        'password': hashed_password,
                        'updated_at': DateTimeHelper.get_utc_now()
                    }
                }
            )
            
            logger.info(f"Password changed for user: {user_id}")
            
            return Response(
                ResponseHelper.success_response(
                    'Password changed successfully'
                ),
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Password change error: {e}", exc_info=True)
            return Response(
                ResponseHelper.error_response(
                    'An error occurred changing your password'
                ),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
