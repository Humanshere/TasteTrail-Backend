"""
Email Utility Functions
Provides functionality for sending emails, particularly for password recovery
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Email configuration from environment variables
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
EMAIL_FROM = os.getenv('EMAIL_FROM', 'noreply@tastetrail.com')
RESET_LINK_EXPIRY_HOURS = int(os.getenv('RESET_LINK_EXPIRY_HOURS', 24))
EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES = int(os.getenv('EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES', 30))
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')


class EmailService:
    """Service for sending emails from the application."""
    
    @classmethod
    def send_email(cls, to_email, subject, text_content=None):
        """
        Send an email with both HTML and plain text versions.
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML content of the email
            text_content: Plain text content (optional, will be derived from HTML if not provided)
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """

        # Create message container
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        
        # Attach parts
        part1 = MIMEText(text_content, 'plain')
        msg.attach(part1)
        
        try:
            # Connect to SMTP server
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)  # Add timeout
            server.starttls()
            
            # Login if credentials are provided
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            
            # Send email
            server.sendmail(EMAIL_FROM, to_email, msg.as_string())
            server.quit()
            
            logger.info(f"✅ Email sent successfully to {to_email}")
            return True
            
        except smtplib.SMTPException as e:
            logger.error(f"❌ SMTP error when sending email: {e}")
            return False
        except ConnectionError as e:
            logger.error(f"❌ Connection error when sending email: {e}")
            return False
        except TimeoutError as e:
            logger.error(f"❌ Timeout error when sending email: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected error when sending email: {e}")
            return False
    
    @classmethod
    def send_password_reset_email(cls, to_email, username, reset_token):
        """
        Send a password reset email with a secure token link.
        
        Args:
            to_email: Recipient email address
            username: User's name or username
            reset_token: Secure token for password reset
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        # Calculate expiry time
        expiry_time = datetime.now() + timedelta(hours=RESET_LINK_EXPIRY_HOURS)
        expiry_str = expiry_time.strftime("%Y-%m-%d %H:%M:%S")
        
        
        # Create email content
        subject = "TasteTrail - Password Reset Request"
        text_content = f"""
        TasteTrail Password Reset
        
        Hello {username},
        
        We received a request to reset your password for your TasteTrail account.
        
        To reset your password, please use this token:
        {reset_token}
        
        This link will expire on {expiry_str}.
        
        If you didn't request a password reset, you can safely ignore this email.
        
        Thank you,
        The TasteTrail Team
        """
        
        return cls.send_email(to_email, subject,  text_content)

    @classmethod
    def send_email_verification(cls, to_email, username, verification_code):
        """
        Send an email verification code during registration.
        """
        expiry_time = datetime.now() + timedelta(minutes=EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES)
        expiry_str = expiry_time.strftime("%Y-%m-%d %H:%M:%S")

        subject = "TasteTrail - Verify your email"
        text_content = f"""
        TasteTrail Email Verification

        Hello {username or to_email.split('@')[0]},

        Thanks for signing up! Please verify your email using this code:
        {verification_code}

        This code expires on {expiry_str}.

        If you didn't create an account, you can safely ignore this email.

        Thank you,
        The TasteTrail Team
        """

        return cls.send_email(to_email, subject, text_content)
