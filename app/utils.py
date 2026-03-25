import secrets
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
import requests
import json

# ----------------------------- JWT TOKEN GENERATION -----------------------------
def get_tokens_for_user(user):

    refresh = RefreshToken.for_user(user)
    return {
        'access_token': str(refresh.access_token),  # matches frontend
        'refresh_token': str(refresh),
    }

# ----------------------------- OTP GENERATION (Cryptographically Secure) -----------------------------
def generate_otp(length=6):
    """Generate a cryptographically secure OTP using secrets module"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(length)])

# ----------------------------- GENERIC EMAIL SENDER -----------------------------
def send_email(subject, to_email, text_content, html_content=None):
    
    email = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[to_email],
    )

    if html_content:
        email.attach_alternative(html_content, "text/html")

    email.send(fail_silently=False)

# ----------------------------- OTP EMAIL TEMPLATE -----------------------------
def build_otp_email_template(otp, context="default"):
    """
    Returns (subject, text_content, html_content)
    """

    # Context-based subject
    subject_map = {
        "register": "Verify Your Email - RCube POS",
        "change_password": "Reset Your Password - RCube POS",
        "change_email_old": "Confirm Your Current Email - RCube POS",
        "change_email_new": "Confirm Your New Email - RCube POS",
    }

    subject = subject_map.get(context, "Your OTP Code - RCube POS")

    # Plain text fallback
    text_content = f"Your OTP is {otp}. It is valid for 10 minutes."

    # HTML Template
    html_content = f"""
    <html>
    <body style="margin:0;padding:0;font-family:Arial,sans-serif;background-color:#f4f4f4;">
        <div style="max-width:600px;margin:30px auto;background:#ffffff;border-radius:8px;overflow:hidden;">
            
            <div style="background:#0f172a;color:#ffffff;padding:20px;text-align:center;">
                <h2 style="margin:0;">RCube POS</h2>
            </div>

            <div style="padding:30px;text-align:center;">
                <h3 style="margin-bottom:10px;">Your Verification Code</h3>
                <p style="color:#555;">Use the OTP below to proceed</p>

                <div style="
                    font-size:28px;
                    font-weight:bold;
                    letter-spacing:8px;
                    margin:20px 0;
                    color:#0f172a;
                ">
                    {otp}
                </div>

                <p style="color:#777;font-size:14px;">
                    This OTP is valid for <strong>10 minutes</strong>.
                </p>

                <p style="color:#999;font-size:12px;margin-top:30px;">
                    If you didn’t request this, you can safely ignore this email.
                </p>
            </div>

            <div style="background:#f1f5f9;padding:15px;text-align:center;font-size:12px;color:#666;">
                © {settings.DEFAULT_FROM_EMAIL}
            </div>

        </div>
    </body>
    </html>
    """

    return subject, text_content, html_content

# ----------------------------- OTP SENDER -----------------------------
def send_otp_email(user_email, otp_code, context="default"):
    subject, text_content, html_content = build_otp_email_template(otp_code, context)

    send_email(
        subject=subject,
        to_email=user_email,
        text_content=text_content,
        html_content=html_content,
    )

# Mobile OTP function (not implemented)
# def send_mobile_otp(mobile, otp):
#     """Send OTP via SMS - requires FAST2SMS configuration"""
#     # Implementation pending - configure with SMS provider credentials
#     pass

# ------------------------------ ERROR HANDLING HELPER -----------------------------
def error_response(message, code=None, details=None, status_code=400, extra=None):
    response = {
        "success": False,
        "error": message,
        "code": code,
        "details": details or {}
    }

    if extra:
        response.update(extra)

    return Response(response, status=status_code)


# ============================= OTP HELPER FUNCTIONS =============================

def check_otp_blocked(user, current_time):
    """
    Check if user's OTP attempts are blocked.
    Returns error_response if blocked, None otherwise.
    """
    if user.otp_blocked_until and current_time < user.otp_blocked_until:
        return error_response(
            "Too many failed OTP attempts. Try again later.",
            code="OTP_BLOCKED",
            status_code=403,
            extra={"blocked_until": str(user.otp_blocked_until)}
        )
    return None


def check_otp_cooldown(user, current_time):
    """
    Check if OTP request is within cooldown period.
    Returns error_response with remaining time if blocked, None otherwise.
    """
    from datetime import timedelta

    cooldown_seconds = settings.OTP_COOLDOWN_SECONDS
    if user.otp_last_sent_at and current_time < user.otp_last_sent_at + timedelta(seconds=cooldown_seconds):
        remaining = int(
            (user.otp_last_sent_at + timedelta(seconds=cooldown_seconds) - current_time).total_seconds()
        )
        return error_response(
            f"Please wait {remaining} seconds before requesting OTP.",
            code="OTP_COOLDOWN",
            status_code=429
        )
    return None


def check_otp_expired(user, current_time):
    """
    Check if OTP has expired.
    Returns error_response if expired, None otherwise.
    """
    from datetime import timedelta

    expiry_minutes = settings.OTP_EXPIRY_MINUTES
    if not user.otp_created_at or current_time > user.otp_created_at + timedelta(minutes=expiry_minutes):
        return error_response(
            "OTP expired. Please request a new one.",
            code="OTP_EXPIRED",
            status_code=400
        )
    return None


def reset_otp_fields(user, full_reset=True):
    """
    Reset OTP-related fields on user object (does not save).

    Args:
        user: User instance
        full_reset: If True, resets everything. If False, only resets OTP code/context.
    """
    user.otp = None
    user.otp_created_at = None
    user.otp_context = None

    if full_reset:
        user.otp_attempts = 0
        user.otp_blocked_until = None

 