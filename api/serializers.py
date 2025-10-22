"""
Data Serializers
Converts MongoDB documents to JSON-safe dictionaries
"""

from typing import Dict, Any, List


class UserSerializer:
    """Serializes user data for API responses."""
    
    @staticmethod
    def serialize_user(user_doc: Dict[str, Any], include_timestamps: bool = True) -> Dict[str, Any]:
        """
        Serialize MongoDB user document to safe API response format.
        Excludes sensitive information like passwords.
        
        Args:
            user_doc: MongoDB user document
            include_timestamps: Whether to include timestamp fields
            
        Returns:
            Serialized user data
        """
        if not user_doc:
            return None
        
        serialized = {
            'id': str(user_doc['_id']),
            'email': user_doc['email'],
            'username': user_doc['username'],
            'role': user_doc['role'],
            'is_active': user_doc.get('is_active', True),
            'is_verified': user_doc.get('is_verified', False)
        }
        
        if include_timestamps:
            serialized['created_at'] = (
                user_doc['created_at'].isoformat() 
                if user_doc.get('created_at') else None
            )
            serialized['updated_at'] = (
                user_doc['updated_at'].isoformat() 
                if user_doc.get('updated_at') else None
            )
            serialized['last_login'] = (
                user_doc['last_login'].isoformat() 
                if user_doc.get('last_login') else None
            )
        
        return serialized
    
    @staticmethod
    def serialize_users(user_docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Serialize multiple user documents."""
        return [
            UserSerializer.serialize_user(user) 
            for user in user_docs 
            if user
        ]


class TokenSerializer:
    """Serializes authentication tokens."""
    
    @staticmethod
    def serialize_tokens(tokens: Dict[str, str], user_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Serialize JWT tokens with optional user data.
        """
        response = {
            'tokens': {
                'access': tokens['access'],
                'refresh': tokens['refresh']
            }
        }
        
        if user_data:
            response['user'] = user_data
        
        return response