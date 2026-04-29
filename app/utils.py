from decimal import Decimal
import secrets
from django.core.mail import send_mail
from django.core.cache import cache
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.db import transaction
from django.core.mail import EmailMultiAlternatives
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
import requests
import json
import stripe
import logging
from django.utils.timezone import now
from .models import *
from datetime import timedelta, datetime, timezone as dt_timezone
import logging
logger = logging.getLogger(__name__)

# ------------------------------ DECIMAL CONVERSION FOR JSON SERIALIZATION ----------------------------- 
def convert_decimals(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_decimals(i) for i in obj]
    return obj

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
        "forgot_password": "Reset Your Password - RCube POS",
        "change_email_old": "Confirm Your Current Email - RCube POS",
        "change_email_new": "Confirm Your New Email - RCube POS",
    }

    subject = subject_map.get(context, "Your OTP Code - RCube POS")

    # Plain text fallback
    if context == "forgot_password":
        text_content = f"Please click the following link to reset your password: {otp}"
        html_content = f"""
        <html>
        <body style="margin:0;padding:0;font-family:Arial,sans-serif;background-color:#f4f4f4;">
            <div style="max-width:600px;margin:30px auto;background:#ffffff;border-radius:8px;overflow:hidden;">
                <div style="background:#0f172a;color:#ffffff;padding:20px;text-align:center;">
                    <h2 style="margin:0;">RCube POS</h2>
                </div>
                <div style="padding:30px;text-align:center;">
                    <h3 style="margin-bottom:10px;">Reset Your Password</h3>
                    <p style="color:#555;margin-bottom:20px;">Use the button below to reset your password</p>
                    <a href="{otp}" style="background-color:#0f172a;color:#ffffff;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block;">Reset Password</a>
                    <p style="color:#777;font-size:14px;margin-top:20px;">
                        This link is valid for a limited time.
                    </p>
                    <p style="color:#999;font-size:12px;margin-top:30px;">
                        If you didn’t request this, you can safely ignore this email.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
    else:
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

# ----------------------------- NOTIFICATION EMAIL SENDER -----------------------------
def build_notification_email_template(context, **kwargs):
    if context == "new_login":
        subject = "New Login Alert - RCube POS"
        ip = kwargs.get("ip_address", "Unknown IP")
        device = kwargs.get("device_info", "Unknown Device")
        text_content = f"We noticed a new login to your RCube POS account from {device} ({ip}). If this was not you, please change your password immediately."
        html_content = f"""
        <html>
        <body style="font-family:Arial,sans-serif;background-color:#f4f4f4;padding:20px;">
            <div style="max-width:600px;margin:0 auto;background:#fff;padding:20px;border-radius:8px;">
                <h3 style="color:#d9534f;">New Login Alert</h3>
                <p>We noticed a new login to your account.</p>
                <ul>
                    <li><strong>Device:</strong> {device}</li>
                    <li><strong>IP Address:</strong> {ip}</li>
                </ul>
                <p>If this was you, you can safely ignore this email.</p>
                <p>If this was not you, please log in and change your password immediately.</p>
            </div>
        </body>
        </html>
        """
    elif context == "password_reset_success":
        subject = "Password Reset Successful - RCube POS"
        text_content = "Your RCube POS password has been successfully reset. If you did not perform this action, contact support immediately."
        html_content = f"""
        <html>
        <body style="font-family:Arial,sans-serif;background-color:#f4f4f4;padding:20px;">
            <div style="max-width:600px;margin:0 auto;background:#fff;padding:20px;border-radius:8px;">
                <h3 style="color:#5cb85c;">Password Reset Successful</h3>
                <p>Your password has been successfully updated.</p>
                <p>If you did not perform this action, please contact support immediately.</p>
            </div>
        </body>
        </html>
        """
    else:
        subject = "Notification - RCube POS"
        text_content = "You have a new notification."
        html_content = ""

    return subject, text_content, html_content

def send_notification_email(user_email, context, **kwargs):
    subject, text_content, html_content = build_notification_email_template(context, **kwargs)
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

# ============================= SUBSCRIPTION HELPER FUNCTIONS =============================

def   get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]

    return request.META.get('REMOTE_ADDR')
    
def get_plan_pricing(plan, country):
    pricing = plan.pricings.filter(country=country, is_active=True).first()
    if not pricing:
        pricing = plan.pricings.filter(country="US", is_active=True).first()
    return pricing

# ============================= PAYMENT HELPER FUNCTIONS =============================

def extract_stripe_metadata(stripe_obj) -> dict:
    if not stripe_obj:
        return {}
    if hasattr(stripe_obj, 'to_dict'):
        return stripe_obj.to_dict()
    # Already a plain dict (e.g. in tests or older SDK versions)
    if isinstance(stripe_obj, dict):
        return stripe_obj
    return {}

stripe.api_key = settings.STRIPE_SECRET_KEY

def create_checkout_session(user, plan, pricing, subscription):
    if not pricing.stripe_price_id:
        raise ValueError(
            f"No Stripe price ID configured for plan '{plan.name}' "
            f"in country '{pricing.country}'"
        )

    try:
        session = stripe.checkout.Session.create(
            mode='subscription',
            customer_email=user.email,
            line_items=[{
                'price': pricing.stripe_price_id,
                'quantity': 1,
            }],
            metadata={
                'user_id': str(user.id),
                'plan_id': str(plan.id),
                'country': pricing.country,
                'subscription_id': str(subscription.id),
            },
            success_url=(
                f"{settings.FRONTEND_URL}/success"
                f"?session_id={{CHECKOUT_SESSION_ID}}"
            ),
            cancel_url=f"{settings.FRONTEND_URL}/dashboard",
        )
        return session

    except stripe.error.InvalidRequestError as e:
        logger.error(
            f"Stripe invalid request for user={user.id} "
            f"plan={plan.id}: {e.user_message}"
        )
        raise

    except stripe.error.StripeError as e:
        logger.error(
            f"Stripe error creating checkout session for user={user.id}: {str(e)}",
            exc_info=True
        )
        raise
def extract_stripe_payment_details(invoice_id, logger):
    """
    Given a Stripe Invoice ID, fetch the invoice and extract payment details.

    In Stripe SDK v15 (API 2026-03-25.dahlia), Invoice.payment_intent and
    Invoice.charge were REMOVED. Payment data now lives under:
        invoice.payments.data[i].payment.payment_intent

    Returns a dict with:
      - stripe_invoice_id
      - stripe_payment_intent_id
      - payment_method  (type string, e.g. 'card')
      - billing_country
      - current_period_start  (datetime, UTC)
      - current_period_end    (datetime, UTC)
    """
    from datetime import datetime, timezone as dt_timezone

    result = {
        "stripe_invoice_id": None,
        "stripe_payment_intent_id": None,
        "payment_method": None,
        "billing_country": None,
        "current_period_start": None,
        "current_period_end": None,
    }

    if not invoice_id:
        logger.warning("[extract] No invoice_id provided — skipping extraction")
        return result

    # ── 1. Fetch the Invoice with the v15 payments expansion ──────────────
    try:
        inv = stripe.Invoice.retrieve(
            invoice_id,
            expand=["payments.data.payment.payment_intent"],
        )
    except stripe.error.StripeError as e:
        logger.warning(f"[extract] Failed to fetch invoice {invoice_id}: {str(e)}")
        return result

    result["stripe_invoice_id"] = inv.id
    logger.info(f"[extract] Invoice fetched: {inv.id}")

    # ── 2. Billing period from line items ─────────────────────────────────
    lines = getattr(inv, "lines", None)
    if lines and lines.data:
        period = getattr(lines.data[0], "period", None)
        if period:
            result["current_period_start"] = datetime.fromtimestamp(
                period.start, tz=dt_timezone.utc
            )
            result["current_period_end"] = datetime.fromtimestamp(
                period.end, tz=dt_timezone.utc
            )

    # ── 3. Extract PaymentIntent from invoice.payments (v15 API) ──────────
    payments_list = getattr(inv, "payments", None)
    if not payments_list or not hasattr(payments_list, "data") or not payments_list.data:
        logger.warning("[extract] No payments found on invoice")
        return result

    # Take the first payment (standard for single-payment subscriptions)
    invoice_payment = payments_list.data[0]
    payment_obj = getattr(invoice_payment, "payment", None)

    if not payment_obj:
        logger.warning("[extract] invoice_payment.payment is None")
        return result

    pi = getattr(payment_obj, "payment_intent", None)
    logger.info(f"[extract] payment.payment_intent type={type(pi)}")

    pi_obj = None
    if isinstance(pi, str):
        result["stripe_payment_intent_id"] = pi
        try:
            pi_obj = stripe.PaymentIntent.retrieve(pi)
        except stripe.error.StripeError as e:
            logger.warning(f"[extract] PaymentIntent.retrieve({pi}) failed: {str(e)}")
    elif pi and hasattr(pi, "id"):
        result["stripe_payment_intent_id"] = pi.id
        pi_obj = pi

    # ── 4. Extract payment_method from the PaymentIntent ──────────────────
    if pi_obj:
        pm_raw = getattr(pi_obj, "payment_method", None)
        logger.info(f"[extract] pi.payment_method type={type(pm_raw)}")

        if isinstance(pm_raw, str):
            # payment_method is a string ID — fetch the full object
            try:
                pm_obj = stripe.PaymentMethod.retrieve(pm_raw)
                result["payment_method"] = getattr(pm_obj, "type", None)
                billing = getattr(pm_obj, "billing_details", None)
                address = getattr(billing, "address", None) if billing else None
                result["billing_country"] = getattr(address, "country", None) if address else None
            except stripe.error.StripeError as e:
                logger.warning(f"[extract] PaymentMethod.retrieve({pm_raw}) failed: {str(e)}")
        elif pm_raw and hasattr(pm_raw, "type"):
            # payment_method is an expanded object
            result["payment_method"] = pm_raw.type
            billing = getattr(pm_raw, "billing_details", None)
            address = getattr(billing, "address", None) if billing else None
            result["billing_country"] = getattr(address, "country", None) if address else None

    logger.info(
        f"[extract] Final → pi={result['stripe_payment_intent_id']}, "
        f"pm={result['payment_method']}, country={result['billing_country']}, "
        f"invoice={result['stripe_invoice_id']}"
    )
    return result


def process_initial_subscription(payment, plan, session):
    from datetime import datetime, timezone as dt_timezone

    logger = logging.getLogger(__name__)

    if payment.status == "success":
        logger.info(f"Payment {payment.id} already processed — skipping")
        return True, "Already processed"

    raw_sub = getattr(session, "subscription", None)
    if not raw_sub:
        raise Exception(f"No Stripe subscription in session for payment {payment.id}")

    stripe_subscription_id = raw_sub if isinstance(raw_sub, str) else raw_sub.id

    sub = payment.subscription
    if not sub:
        raise Exception(f"Payment {payment.id} has no linked Subscription record")

    # ── Get the invoice ID from the session ────────────────────────────────
    # By the time checkout.session.completed fires, session.invoice is populated.
    raw_invoice = getattr(session, "invoice", None)
    invoice_id = raw_invoice if isinstance(raw_invoice, str) else (
        raw_invoice.id if raw_invoice and hasattr(raw_invoice, "id") else None
    )

    # Fallback: fetch from the Stripe Subscription if session didn't have it
    if not invoice_id:
        logger.info(f"[initial] session.invoice was empty, fetching from Subscription")
        try:
            stripe_sub_obj = stripe.Subscription.retrieve(stripe_subscription_id)
            li = getattr(stripe_sub_obj, "latest_invoice", None)
            invoice_id = li if isinstance(li, str) else (
                li.id if li and hasattr(li, "id") else None
            )
        except stripe.error.StripeError as e:
            logger.warning(f"[initial] Subscription.retrieve failed: {str(e)}")

    logger.info(f"[initial] Resolved invoice_id: {invoice_id}")

    # ── Extract all payment details from the Invoice ───────────────────────
    details = extract_stripe_payment_details(invoice_id, logger)

    # Apply extracted details to the payment record
    payment.stripe_invoice_id = details["stripe_invoice_id"]
    payment.stripe_payment_intent_id = details["stripe_payment_intent_id"]
    payment.payment_method = details["payment_method"]
    if details["billing_country"] and not payment.country:
        payment.country = details["billing_country"]

    current_period_start = details["current_period_start"]
    current_period_end = details["current_period_end"]

    # ── Activate payment ──────────────────────────────────────────────────
    payment.status = "success"
    payment.paid_at = now()
    payment.save()

    # ── Activate subscription ─────────────────────────────────────────────
    sub.plan = plan
    sub.status = "active"
    sub.stripe_subscription_id = stripe_subscription_id
    sub.start_date = now().date()
    sub.current_period_start = current_period_start
    sub.current_period_end = current_period_end

    if plan.interval == "monthly":
        sub.end_date = sub.start_date + timedelta(days=30)
    elif plan.interval == "yearly":
        sub.end_date = sub.start_date + timedelta(days=365)

    sub.last_payment = payment
    sub.save()

    create_invoice_for_payment(payment, plan)

    logger.info(
        f"Subscription {sub.id} activated for user {sub.user_id} "
        f"on plan '{plan.name}' | period: {current_period_start} → {current_period_end}"
    )
    return True, "Subscription activated"

def create_invoice_for_payment(payment, plan):
    # ── Remove the duplicate block — only one copy of this function ───────
    logger = logging.getLogger(__name__)

    if Invoice.objects.filter(payment=payment).exists():
        return

    sub = payment.subscription

    try:
        invoice_number = f"INV-{now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        Invoice.objects.create(
            subscription=sub,
            payment=payment,
            stripe_payment_intent_id=payment.stripe_payment_intent_id,
            stripe_invoice_id=payment.stripe_invoice_id,
            base_amount=payment.base_amount,
            plan_name=plan.name,
            plan_interval=plan.interval,
            invoice_number=invoice_number,
            coupon_code=payment.coupon_code,
            discount_amount=payment.discount_amount,
            gst_amount=payment.gst_amount,
            total_amount=payment.final_amount,
            currency=payment.currency,
            status='paid',
            billing_details={
                "country": payment.country or "",
                "payment_method": payment.payment_method or "",
            }
        )
    except Exception as e:
        logger.error(
            f"Failed to create invoice for payment {payment.id}: {str(e)}",
            exc_info=True
        )
