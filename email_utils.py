from flask_mail import Message
from extensions import mail
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

def send_termination_notification(email, user_name, reasons, custom_reason):
    """Send account termination notification email"""
    try:
        # Build reason list
        reason_list = []
        if reasons:
            reason_list.extend(reasons)
        
        # Create termination email HTML
        html_body = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #dc3545; color: white; padding: 30px; text-align: center; border-radius: 10px; }}
                .content {{ padding: 30px; background: #f8f9fa; border-radius: 10px; margin: 20px 0; }}
                .reasons {{ background: white; padding: 20px; border-left: 4px solid #dc3545; margin: 20px 0; border-radius: 5px; }}
                .footer {{ color: #6c757d; font-size: 0.9rem; text-align: center; margin-top: 30px; }}
                ul {{ padding-left: 20px; }}
                li {{ margin: 8px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0;">Account Termination Notice</h1>
                    <p style="margin: 10px 0 0 0; font-size: 1.1rem;">Community Connect Platform</p>
                </div>
                <div class="content">
                    <p style="font-size: 1.1rem;">Dear {user_name or 'User'},</p>
                    <p>We regret to inform you that your Community Connect account has been terminated by our administration team.</p>
                    
                    <div class="reasons">
                        <h3 style="color: #dc3545; margin-top: 0;">Termination Reasons:</h3>
                        <ul>
        '''
        
        for reason in reason_list:
            html_body += f'                            <li>{reason}</li>\n'
        
        if custom_reason and custom_reason.strip():
            html_body += f'                            <li><strong>Additional Details:</strong> {custom_reason.strip()}</li>\n'
        
        html_body += '''
                        </ul>
                    </div>
                    
                    <p>As a result of this termination:</p>
                    <ul>
                        <li>Your account has been permanently deactivated</li>
                        <li>All your personal data has been removed from our systems</li>
                        <li>Any events, applications, or RSVPs associated with your account have been deleted</li>
                        <li>You will no longer have access to Community Connect services</li>
                    </ul>
                    
                    <p>If you believe this termination was made in error or if you have questions about this decision, please contact our support team immediately.</p>
                    
                    <p>Thank you for being part of our community.</p>
                    <p><strong>The Community Connect Team</strong></p>
                </div>
                <div class="footer">
                    <p>This is an automated notification from Community Connect.<br>
                    Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        '''
        
        msg = Message(
            subject='Account Termination Notification - Community Connect',
            recipients=['samplebookshopnyp@gmail.com'],  # All emails go here for school project
            html=html_body
        )
        mail.send(msg)
        logging.info(f"Termination notification sent for user: {user_name} ({email})")
        return True
    except Exception as e:
        logging.error(f"Failed to send termination notification: {e}")
        return False

def send_event_review_notification(email, organizer_name, event_title, action, admin_remarks):
    """Send event review notification to organizer"""
    try:
        subject = f"Event Review: {event_title} - Community Connect"
        action_text = "Approved" if action == "approved" else "Rejected"
        status_color = "#28a745" if action == "approved" else "#dc3545"
        
        html_body = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: {status_color}; color: white; padding: 30px; text-align: center; border-radius: 10px; }}
                .content {{ padding: 30px; background: #f8f9fa; border-radius: 10px; margin: 20px 0; }}
                .event-details {{ background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .remarks {{ background: white; padding: 20px; border-left: 4px solid {status_color}; margin: 20px 0; border-radius: 5px; }}
                .footer {{ color: #6c757d; font-size: 0.9rem; text-align: center; margin-top: 30px; }}
                .status-badge {{ background: {status_color}; color: white; padding: 8px 16px; border-radius: 20px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0;">Event {action_text}</h1>
                    <p style="margin: 10px 0 0 0; font-size: 1.1rem;">Community Connect Platform</p>
                </div>
                <div class="content">
                    <p style="font-size: 1.1rem;">Dear {organizer_name},</p>
                    <p>Your event has been reviewed by our administration team.</p>
                    
                    <div class="event-details">
                        <h3 style="margin-top: 0; color: #333;">Event Details:</h3>
                        <p><strong>Event Title:</strong> {event_title}</p>
                        <p><strong>Status:</strong> <span class="status-badge">{action_text}</span></p>
                    </div>
                    
                    <div class="remarks">
                        <h3 style="color: {status_color}; margin-top: 0;">Admin Feedback:</h3>
                        <p>{admin_remarks}</p>
                    </div>
                    
                    {"<p>Congratulations! Your event has been approved and is now visible to community members.</p>" if action == "approved" else "<p>We apologize that your event cannot be approved at this time. Please review the feedback above and feel free to resubmit your event with the necessary changes.</p>"}
                    
                    <p>Thank you for organizing events for our community!</p>
                    <p><strong>The Community Connect Team</strong></p>
                </div>
                <div class="footer">
                    <p>This is an automated notification from Community Connect.<br>
                    Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        '''
        
        msg = Message(
            subject=subject,
            recipients=['samplebookshopnyp@gmail.com'],  # All emails go here for school project
            html=html_body
        )
        mail.send(msg)
        logging.info(f"Event review notification sent for event: {event_title} ({action})")
        return True
    except Exception as e:
        logging.error(f"Failed to send event review notification: {e}")
        return False

