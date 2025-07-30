from flask_mail import Message
from app import mail
import logging
from datetime import datetime

def send_verification_email(email, verification_code, purpose='login', user_name=None):
    """Send verification email with the 6-digit code"""
    try:
        subject_map = {
            'login': 'Community Connect - Login Verification Code',
            'password_reset': 'Community Connect - Password Reset Code',
            'email_change': 'Community Connect - Email Change Verification'
        }
        
        subject = subject_map.get(purpose, 'Community Connect - Verification Code')
        
        # Create HTML email template
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%); padding: 30px; text-align: center; border-radius: 10px; }}
                .code-box {{ background-color: #f8f9fa; border: 3px solid #0d6efd; border-radius: 10px; padding: 30px; margin: 30px 0; text-align: center; }}
                .verification-code {{ font-size: 2.5rem; font-weight: bold; color: #0d6efd; letter-spacing: 0.5rem; font-family: monospace; }}
                .warning {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .footer {{ color: #6c757d; font-size: 0.9rem; text-align: center; margin-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0; color: #495057;">
                        <span style="color: #dc3545;">❤️</span> Community Connect
                    </h1>
                    <p style="margin: 10px 0 0 0; font-size: 1.1rem; color: #6c757d;">Verification Code Required</p>
                </div>
                
                <p style="font-size: 1.1rem;">Hello {user_name if user_name else ''},</p>
                
                <p style="font-size: 1.1rem;">You requested to log in to your Community Connect account. Please use the verification code below:</p>
                
                <div class="code-box">
                    <p style="margin: 0 0 10px 0; font-size: 1.1rem; color: #495057;">Your Verification Code:</p>
                    <div class="verification-code">{verification_code}</div>
                    <p style="margin: 15px 0 0 0; color: #6c757d; font-size: 0.9rem;">This code expires in 10 minutes</p>
                </div>
                
                <div class="warning">
                    <p style="margin: 0; font-weight: 600;"><strong>Security Notice:</strong></p>
                    <p style="margin: 5px 0 0 0;">If you didn't request this code, please ignore this email. Never share this code with anyone.</p>
                </div>
                
                <p style="font-size: 1.1rem;">
                    Enter this code on the Community Connect login page to complete your sign-in process.
                </p>
                
                <div class="footer">
                    <p>This is an automated email from Community Connect.<br>
                    If you have any questions, please contact support at (555) 123-4567.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create plain text version
        text_body = f"""
        Community Connect - Verification Code
        
        Hello {user_name if user_name else ''},
        
        You requested to log in to your Community Connect account.
        
        Your verification code is: {verification_code}
        
        This code expires in 10 minutes.
        
        Enter this code on the Community Connect login page to complete your sign-in.
        
        If you didn't request this code, please ignore this email.
        
        Community Connect Support
        (555) 123-4567
        """
        
        msg = Message(
            subject=subject,
            recipients=['samplebookshopnyp@gmail.com'],  # School project - all emails go here
            html=html_body,
            body=text_body
        )
        
        mail.send(msg)
        logging.info(f"Verification email sent to {email} for {purpose}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send verification email to {email}: {str(e)}")
        return False

def send_login_success_notification(email, user_name):
    """Send notification email when user successfully logs in"""
    try:
        subject = "Community Connect - Successful Login"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); padding: 30px; text-align: center; border-radius: 10px; }}
                .content {{ padding: 20px 0; }}
                .footer {{ color: #6c757d; font-size: 0.9rem; text-align: center; margin-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0; color: #155724;">
                        <span style="color: #dc3545;">❤️</span> Community Connect
                    </h1>
                    <p style="margin: 10px 0 0 0; font-size: 1.1rem; color: #155724;">Login Successful</p>
                </div>
                
                <div class="content">
                    <p style="font-size: 1.1rem;">Hello {user_name},</p>
                    
                    <p style="font-size: 1.1rem;">
                        You have successfully logged into your Community Connect account with 2FA verification.
                    </p>
                    
                    <p style="font-size: 1.1rem;">
                        <strong>Login Time:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
                    </p>
                    
                    <p style="font-size: 1.1rem;">
                        If this wasn't you, please contact support immediately at (555) 123-4567.
                    </p>
                </div>
                
                <div class="footer">
                    <p>This is an automated security notification from Community Connect.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = Message(
            subject=subject,
            recipients=['samplebookshopnyp@gmail.com'],  # School project - all emails go here
            html=html_body
        )
        
        mail.send(msg)
        logging.info(f"Login success notification sent to {email}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send login notification to {email}: {str(e)}")
        return False

def send_termination_notification(email, first_name, reasons, custom_reason):
    """Send account termination notification email"""
    try:
        # Format reasons list
        reason_text = ""
        if reasons:
            reason_text = "Reason(s) for termination:\n"
            for reason in reasons:
                reason_text += f"• {reason}\n"
        
        if custom_reason:
            reason_text += f"\nAdditional details:\n{custom_reason}"
        
        subject = "Account Termination Notification - Community Connect"
        
        # Create HTML email body
        html_body = f"""
        <html>
        <head>
            <style>
                .container {{ max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; }}
                .header {{ background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background-color: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef; }}
                .reason-box {{ background-color: #fff; padding: 20px; border-left: 4px solid #dc3545; margin: 20px 0; }}
                .footer {{ font-size: 14px; color: #6c757d; margin-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Community Connect</h1>
                    <p style="color: #f0f0f0; margin: 10px 0 0 0; font-size: 16px;">Account Termination Notice</p>
                </div>
                
                <div class="content">
                    <h2 style="color: #dc3545; margin-top: 0;">Account Terminated</h2>
                    
                    <p>Hello {first_name or 'User'},</p>
                    
                    <p>This is to inform you that your Community Connect account has been terminated by our administration team.</p>
                    
                    {f'<div class="reason-box"><pre style="font-family: Arial, sans-serif; white-space: pre-wrap; margin: 0;">{reason_text}</pre></div>' if reason_text else ''}
                    
                    <p>If you believe this termination was made in error or if you have any questions, please contact our support team.</p>
                    
                    <p>Thank you for your time with Community Connect.</p>
                    
                    <div class="footer">
                        <hr style="border: none; border-top: 1px solid #e9ecef; margin: 30px 0;">
                        <p>
                            <strong>Community Connect</strong><br>
                            Connecting Communities, Building Relationships
                        </p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = Message(
            subject=subject,
            recipients=['samplebookshopnyp@gmail.com'],  # School project - all emails go here
            html=html_body
        )
        
        mail.send(msg)
        logging.info(f"Account termination notification sent to {email}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send termination notification: {str(e)}")
        return False