from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from simple_history.models import HistoricalRecords
from datetime import date
from django.utils.timezone import now
from django.core.exceptions import ValidationError
from django.db.models import Q
import uuid

# ========================= # AUTH MODELS # =========================

# User Manager
class UserManager(BaseUserManager):
    # use_in_migrations = True
    def create_user(self, email, username, phone, password=None):
        if not email:
            raise ValueError("Email is required")
        if not username:
            raise ValueError("Username is required")
        if not phone:
            raise ValueError("Phone number is required")

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            phone=phone
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, phone, password=None):
        user = self.create_user(email, username, phone, password)
        user.is_active = True
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user

# Role Model
class Role(models.Model):
    ROLE_CATEGORIES = [
        ("admin", "Admin"),
        ("owner", "Owner"),
    ]

    role_name = models.CharField(max_length=100, unique=True)
    role_category = models.CharField(
        max_length=100,
        choices=ROLE_CATEGORIES,
        default="owner"  # Must be a valid choice from ROLE_CATEGORIES
    )
    created_at = models.DateTimeField(auto_now_add=True)

    history = HistoricalRecords()

    def __str__(self):
        return self.role_name

    class Meta:
        db_table = 'role'

#  User Model with Role
class Users(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    billing_country = models.CharField(max_length=2, blank=True, null=True)
    phone_country_code = models.CharField(max_length=5, blank=True, null=True)
    phone = models.CharField(
        max_length=15,
        blank=True,
        null=True,
        # NOTE: unique=True allows multiple NULLs. Use database constraint or validation.
        unique=True
    )
    email = models.EmailField(
        max_length=100,
        # USERNAME_FIELD must NOT be nullable - required for authentication
        blank=False,
        null=False,
        unique=True
    )
    username = models.CharField(max_length=100, unique=True, blank=False, null=False)
    profile_image = models.ImageField(upload_to='profile_img/', blank=True, null=True)
    firebase_id = models.TextField(blank=True, null=True, default=None)
    date_of_birth = models.DateField(blank=True, null=True, default=None)

    address = models.TextField(blank=True, null=True, default=None)
    city = models.CharField(max_length=100, blank=True, null=True, default=None)
    district = models.CharField(max_length=100, blank=True, null=True, default=None)
    state = models.CharField(max_length=100, blank=True, null=True, default=None)
    pincode = models.CharField(
        max_length=10,  # Changed from IntegerField to handle postal codes with letters
        blank=True,
        null=True,
        default=None
    )

    otp = models.CharField(max_length=6, blank=True, null=True, default=None)
    otp_created_at = models.DateTimeField(blank=True, null=True, default=None)
    otp_attempts = models.IntegerField(default=0)
    otp_blocked_until = models.DateTimeField(blank=True, null=True, default=None)
    otp_last_sent_at = models.DateTimeField(blank=True, null=True, default=None)

    otp_context = models.CharField(max_length=50, blank=True, null=True, default=None)
    pending_email = models.EmailField(max_length=100, blank=True, null=True, default=None)

    is_email_verified = models.BooleanField(default=False)

    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True, related_name="users")

    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "phone"]

    objects = UserManager()
    history = HistoricalRecords()

    def clean(self):
        """Validate model constraints that can't be enforced at database level."""
        from django.core.validators import validate_email

        # Validate email format
        if self.email:
            try:
                validate_email(self.email)
            except ValidationError:
                raise ValidationError({'email': 'Invalid email format'})

        # Validate OTP format if present
        if self.otp and not self.otp.isdigit():
            raise ValidationError({'otp': 'OTP must contain only digits'})

        if self.otp and len(self.otp) != 6:
            raise ValidationError({'otp': 'OTP must be 6 digits'})

    def __str__(self):
        return self.username

    class Meta:
        db_table = 'users'

        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['username']),
            models.Index(fields=['phone']),
        ]

# User Role Assignment Model (Many-to-Many)
class UserRole(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE, related_name="user_roles")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="role_users")
    created_by = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True, related_name="created_roles")
    created_at = models.DateTimeField(auto_now_add=True)

    history = HistoricalRecords()

    def __str__(self):
        return f"{self.user.username} - {self.role.role_name}"

    class Meta:
        db_table = 'user_role'
        unique_together = ("user", "role")

User = settings.AUTH_USER_MODEL

# ========================= # RESTAURANT MODELS # =========================

class Restaurant(models.Model):
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Inactive', 'Inactive')
    ]

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='restaurants')

    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    address = models.TextField()
    gst_number = models.CharField(max_length=20, blank=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Active')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    is_deleted = models.BooleanField(default=False)

    history = HistoricalRecords()

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'restaurants'
        indexes = [
            models.Index(fields=['owner']),
            models.Index(fields=['status']),
        ]

# ========================= # SUBSCRIPTION MODELS # =========================

class SubscriptionPlan(models.Model):
    INTERVAL_CHOICES = [('monthly', 'Monthly'), ('yearly', 'Yearly')]

    name = models.CharField(max_length=50)
    # price = models.DecimalField(max_digits=10, decimal_places=2)
    interval = models.CharField(max_length=10, choices=INTERVAL_CHOICES, default='monthly')
    features = models.JSONField(default=list)
    popular = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    history = HistoricalRecords()

    def clean(self):
        """Validate plan constraints."""
        # Price validation
        if self.price and self.price < 0:
            raise ValidationError({'price': 'Price cannot be negative.'})

        if self.price and self.price > 999999.99:
            raise ValidationError({'price': 'Price exceeds maximum limit.'})

        # Interval validation
        if self.interval not in dict(self.INTERVAL_CHOICES):
            raise ValidationError({'interval': "Invalid interval. Must be 'monthly' or 'yearly'."})

        # Features validation
        if not isinstance(self.features, list):
            raise ValidationError({'features': 'Features must be a list.'})

        if len(self.features) > 50:
            raise ValidationError({'features': 'Maximum 50 features allowed.'})

        for feature in self.features:
            if not isinstance(feature, str) or not feature.strip():
                raise ValidationError({'features': 'Each feature must be a non-empty string.'})

            if len(feature) > 255:
                raise ValidationError({'features': 'Feature names must be under 255 characters.'})

    def __str__(self):
        return f"{self.name} ({self.interval})"
    
    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['name', 'interval'], name='unique_plan_per_interval')
        ]

class PlanPricing(models.Model):
    plan = models.ForeignKey('SubscriptionPlan', on_delete=models.CASCADE, related_name='pricings')
    country = models.CharField(max_length=2)
    currency = models.CharField(max_length=10)
    price = models.DecimalField(max_digits=10, decimal_places=2)

    stripe_price_id = models.CharField(max_length=255, blank=True, null=True)

    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        if self.price < 0:
            raise ValidationError("Price cannot be negative.")
        if len(self.country) != 2:
            raise ValidationError("Country code must be ISO based 2 characters.")
        
    def __str__(self):
        return f"{self.plan.name} - {self.country} {self.currency} {self.price}"
    
    class Meta:
        unique_together = ('plan', 'country')

class Subscription(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('none', 'None')
    ]

    restaurant = models.OneToOneField(Restaurant, on_delete=models.CASCADE, related_name='subscription', null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='subscriptions')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.SET_NULL, null=True)

    last_session_created_at = models.DateTimeField(blank=True, null=True)
    last_payment = models.ForeignKey('PaymentTransaction', on_delete=models.SET_NULL, null=True, blank=True, related_name='subscriptions')
    
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='none')

    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    history = HistoricalRecords()

    def get_status(self):
        if not self.plan:
            return 'none'
        if self.end_date and self.end_date < now().date():
            return 'expired'
        return 'active'

    class Meta:
        db_table = 'subscriptions'
        indexes = [
            models.Index(fields=['restaurant']),
            models.Index(fields=['status']),
        ]
        constraints = [
            models.UniqueConstraint(fields=['user'], name='unique_user_subscription')
        ]

class Invoice(models.Model):
    STATUS_CHOICES = [
        ('paid', 'Paid'),
        ('pending', 'Pending'),
        ('failed', 'Failed')
    ]

    subscription = models.ForeignKey(Subscription, on_delete=models.CASCADE, related_name='invoices')

    stripe_payment_intent_id = models.CharField(max_length=255, blank=True, null=True)
    
    date = models.DateField(auto_now_add=True)
    base_amount = models.DecimalField(max_digits=10, decimal_places=2)
    plan_name = models.CharField(max_length=50)
    plan_interval = models.CharField(max_length=10, choices=SubscriptionPlan.INTERVAL_CHOICES, default='monthly')

    invoice_number = models.CharField(max_length=50, unique=True, null=True, blank=True)

    coupon_code = models.CharField(max_length=50, blank=True, null=True)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    payment = models.OneToOneField('PaymentTransaction', on_delete=models.SET_NULL, null=True, blank=True, related_name='invoice')
    gst_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    currency = models.CharField(max_length=10, default='USD')

    billing_details = models.JSONField(default=dict, blank=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    created_at = models.DateTimeField(auto_now_add=True)

    history = HistoricalRecords()

    def __str__(self):
        return f"Invoice {self.id} - {self.plan_name} - {self.currency} {self.total_amount} - {self.status}"

    class Meta:
        db_table = 'invoices'

# ========================= # PLATFORM SETTINGS # =========================

class PlatformSettings(models.Model):
    gst_percent = models.DecimalField(max_digits=5, decimal_places=2, default=5)
    currency = models.CharField(max_length=5, default='INR')

    history = HistoricalRecords()

    class Meta:
        verbose_name_plural = 'Platform Settings'
        db_table = 'platform_settings'

# ========================= # PAYMENT MODELS # =========================

class PaymentTransaction(models.Model):
    PAYMENT_STATUS = [
        ('initiated', 'Initiated'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    ]

    transaction_id = models.CharField(max_length=50, unique=True, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    subscription = models.ForeignKey(Subscription, on_delete=models.SET_NULL, null=True, blank=True)

    # Stripe Data
    stripe_session_id = models.CharField(max_length=255, blank=True, null=True)
    stripe_payment_intent_id = models.CharField(max_length=255, blank=True, null=True)

    country = models.CharField(max_length=2, blank=True, null=True)
    currency = models.CharField(max_length=10, default='INR')
    base_amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    coupon_code = models.CharField(max_length=50, blank=True, null=True)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    gst_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    final_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default='initiated')

    payment_method = models.CharField(max_length=50, blank=True, null=True)

    failure_reason = models.TextField(blank=True, null=True)

    refunded_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    paid_at = models.DateTimeField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    history = HistoricalRecords()

    def generate_transaction_id(self):
        return f"TXN-{now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"

    def calculate_final_amount(self):
        settings = PlatformSettings.objects.first()
        gst_percent = settings.gst_percent if settings else 0

        self.total_amount = self.base_amount - self.discount_amount
        if self.currency == 'INR':
            self.gst_amount = self.total_amount * gst_percent / 100
        else:
            self.gst_amount = 0
        self.final_amount = self.total_amount + self.gst_amount

    def __str__(self):
        return f"{self.user} - {self.currency} {self.total_amount} - {self.status}"
    
    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = self.generate_transaction_id()

        self.calculate_final_amount()

        super().save(*args, **kwargs)

    class Meta:
        db_table = 'payment_transactions'
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['stripe_payment_intent_id']),
            models.Index(fields=['created_at']),
            models.Index(fields=['user']),
            models.Index(fields=['currency']),
            models.Index(fields=['country']),
            models.Index(fields=['transaction_id']),
        ]
        constraints = [
            models.UniqueConstraint(fields=['stripe_payment_intent_id'], name='unique_stripe_payment_intent')
        ]

class Refund(models.Model):
    payment = models.ForeignKey(PaymentTransaction, on_delete=models.CASCADE, related_name='refunds')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default='USD')
    reason = models.TextField(blank=True, null=True)
    stripe_refund_id = models.CharField(max_length=255, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    history = HistoricalRecords()

    def clean(self):
        total_refunded = sum(r.amount for r in self.payment.refunds.all())
        if total_refunded + self.amount > self.payment.final_amount:
            raise ValidationError({'amount': 'Refund amount cannot exceed the remaining payment amount.'})

    def __str__(self):
        return f"Refund for {self.payment} - {self.currency} {self.amount}"

    class Meta:
        db_table = 'refunds'

# ======================== # STRIPE MODELS # ========================

class StripeWebhookLog(models.Model):
    event_id = models.CharField(max_length=255, unique=True)
    event_type = models.CharField(max_length=100)

    payload = models.JSONField()

    processed = models.BooleanField(default=False)
    processing_error = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.event_type} - {self.event_id}"

    class Meta:
        db_table = 'stripe_webhook_logs'

# ========================= # OTHER MODELS =========================


