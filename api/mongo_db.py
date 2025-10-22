"""
MongoDB Connection Manager
Handles database connections, collections, and indexes
"""

import os
from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv
import logging

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MongoDBManager:
    """
    Singleton class to manage MongoDB connections and collections.
    Ensures single connection instance throughout the application.
    """
    
    _instance = None
    _client = None
    _db = None

    def __new__(cls):
        """Create singleton instance."""
        if cls._instance is None:
            cls._instance = super(MongoDBManager, cls).__new__(cls)
            cls._instance._initialize_connection()
        return cls._instance

    def _initialize_connection(self):
        """Establish connection to MongoDB with error handling."""
        try:
            # Get configuration from environment
            MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
            DB_NAME = os.getenv('DB_NAME', 'user_management_db')
            
            # Create MongoDB client with connection pooling
            self._client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=10000,
                maxPoolSize=50,
                minPoolSize=10
            )
            
            # Test connection
            self._client.admin.command('ping')
            logger.info("✅ MongoDB connection successful")
            
            # Get database
            self._db = self._client[DB_NAME]
            
            # Setup indexes
            self._setup_indexes()
            
        except ConnectionFailure as e:
            logger.error(f"❌ Failed to connect to MongoDB: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected error during MongoDB initialization: {e}")
            raise

    def _setup_indexes(self):
        """Create necessary indexes for optimal performance."""
        try:
            # Users collection indexes
            self._db.users.create_index(
                [('email', ASCENDING)], 
                unique=True, 
                name='email_unique_idx'
            )
            self._db.users.create_index(
                [('username', ASCENDING)], 
                unique=True, 
                name='username_unique_idx'
            )
            self._db.users.create_index(
                [('created_at', ASCENDING)], 
                name='created_at_idx'
            )
            self._db.users.create_index(
                [('is_active', ASCENDING)], 
                name='is_active_idx'
            )
            
            # Password resets collection indexes
            self._db.password_resets.create_index(
                [('token', ASCENDING)], 
                unique=True, 
                name='token_unique_idx'
            )
            self._db.password_resets.create_index(
                [('expires_at', ASCENDING)], 
                name='expires_at_idx'
            )
            self._db.password_resets.create_index(
                [('email', ASCENDING)], 
                name='email_idx'
            )
            self._db.password_resets.create_index(
                [('used', ASCENDING)], 
                name='used_idx'
            )

            # Email verifications collection indexes
            self._db.email_verifications.create_index(
                [('token', ASCENDING)],
                unique=True,
                name='email_verify_token_unique_idx'
            )
            self._db.email_verifications.create_index(
                [('expires_at', ASCENDING)],
                name='email_verify_expires_at_idx'
            )
            self._db.email_verifications.create_index(
                [('email', ASCENDING)],
                name='email_verify_email_idx'
            )
            self._db.email_verifications.create_index(
                [('used', ASCENDING)],
                name='email_verify_used_idx'
            )
            
            logger.info("✅ Database indexes created successfully")
            
        except Exception as e:
            logger.warning(f"⚠️ Index creation warning: {e}")

    @property
    def users(self):
        """Get users collection."""
        return self._db.users

    @property
    def password_resets(self):
        """Get password_resets collection."""
        return self._db.password_resets

    @property
    def email_verifications(self):
        """Get email_verifications collection."""
        return self._db.email_verifications


# Initialize global database manager
db_manager = MongoDBManager()

# Export collections for easy import
users_collection = db_manager.users
password_resets_collection = db_manager.password_resets
email_verifications_collection = db_manager.email_verifications