import random
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from rest_framework_simplejwt.tokens import RefreshToken
import requests
import json

# ----------------------------- JWT TOKEN GENERATION -----------------------------
def get_tokens_for_user(user):

    refresh = RefreshToken.for_user(user)
    return {
        'access_token': str(refresh.access_token),  # matches frontend
        'refresh_token': str(refresh),
    }

# ----------------------------- OTP GENERATION -----------------------------
def generate_otp(length=6):
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])

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

# def send_mobial_otp(mobile, otp):
#     url = "https://www.fast2sms.com/dev/bulkV2"
#     payload = {
        
#         "route" : "otp",
#         "variables_values" : "123456",
#         "numbers" : "9985462090",
#         # "route": "otp",
#         # "variables_values": otp,
#         # "numbers":mobile
#     }

#     headers = {
        
#        "authorization":"LOZC9VFJiSaMe2DGE4uzkXngTqv07d1xwjh5BW3Uo86RysAtQNIw4OVfF57D6rySmh12sRLqYWdcl0ni",
#         # "authorization": settings.FAST2SMS_API_KEY, 
#         "Content-Type": "application/json"
#     }

#     try:
#         response = requests.post(url, headers=headers, data=json.dumps(payload))
#         response.raise_for_status()
#         print(response.text)
#         return response.text
#     except requests.exceptions.RequestException as e:
#         print(f"Error: {e}")
#         return str(e)

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

