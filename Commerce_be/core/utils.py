from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings


def send_verification_email(to_email, name, verification_code):
    """Send verification code email to user"""
    subject = "Verify Your Account"
    from_email = settings.DEFAULT_FROM_EMAIL
    to = [to_email]

    context = {
        'name': name,
        'verification_code': verification_code
    }

    html_content = render_to_string('emails/verification_email.html', context)
    
    text_content = f"""Hi {name},

Welcome ! 

To complete your account setup, please verify your email address using the verification code below:

Verification Code: {verification_code}

This code will expire in 10 minutes for security reasons.

If you didn't create an account with TunaresQ, please ignore this email.

With gratitude,
The  Team"""

    msg = EmailMultiAlternatives(subject, text_content, from_email, to)
    msg.attach_alternative(html_content, "text/html")
    
    try:
        msg.send()
        return True
    except Exception as e:
        print(f"Error sending verification email: {e}")
        return False


def send_password_reset_email(to_email, name, reset_token):
    """Send password reset email to user"""
    subject = "Reset Your TunaresQ Password"
    from_email = settings.DEFAULT_FROM_EMAIL
    to = [to_email]

    context = {
        'name': name,
        'reset_token': reset_token,
    }

    html_content = render_to_string('emails/password_reset_email.html', context)
    
    text_content = f"""Hi {name},

We received a request to reset your TunaresQ account password.

To reset your password, use the following token: {reset_token}

This reset token will expire in 1 hour for security reasons.

If you didn't request a password reset, please ignore this email or contact our support team if you have concerns.
.With gratitude,
The TunaresQ Team"""

    msg = EmailMultiAlternatives(subject, text_content, from_email, to)
    msg.attach_alternative(html_content, "text/html")
    
    try:
        msg.send()
        return True
    except Exception as e:
        print(f"Error sending password reset email: {e}")
        return False
