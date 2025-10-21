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
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')


class EmailService:
    """Service for sending emails from the application."""
    
    @classmethod
    def send_email(cls, to_email, subject, html_content, text_content=None):
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
        if not text_content:
            # Simple conversion from HTML to plain text
            text_content = html_content.replace('<br>', '\n').replace('</p>', '\n\n')
            
        # Create message container
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        
        # Attach parts
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
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
        
        # Create reset link
        reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"
        
        # Create email content
        subject = "TasteTrail - Password Reset Request"
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #e63946;">TasteTrail Password Reset</h2>
                <p>Hello {username},</p>
                <p>We received a request to reset your password for your TasteTrail account.</p>
                <p>To reset your password, please click the button below:</p>
                <p style="text-align: center;">
                    <a href="{reset_link}" style="background-color: #e63946; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
                </p>
                <p>Or copy and paste this link into your browser:</p>
                <p>{reset_link}</p>
                <p>This link will expire on {expiry_str}.</p>
                <p>If you didn't request a password reset, you can safely ignore this email.</p>
                <p>Thank you,<br>The TasteTrail Team</p>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
        TasteTrail Password Reset
        
        Hello {username},
        
        We received a request to reset your password for your TasteTrail account.
        
        To reset your password, please visit this link:
        {reset_link}
        
        This link will expire on {expiry_str}.
        
        If you didn't request a password reset, you can safely ignore this email.
        
        Thank you,
        The TasteTrail Team
        """
        
        return cls.send_email(to_email, subject, html_content, text_content)