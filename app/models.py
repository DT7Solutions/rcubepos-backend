from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from simple_history.models import HistoricalRecords
from datetime import date
from django.utils.timezone import now
from django.core.exceptions import ValidationError
from django.db.models import Q

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
    phone = models.CharField(
        max_length=20,
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
    price = models.DecimalField(max_digits=10, decimal_places=2)
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
        return f"{self.name} - ₹{self.price}/{self.interval}"
    
    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['name', 'interval'], name='unique_plan_per_interval')
        ]
        ordering = ['price']
    
class Subscription(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('none', 'None')
    ]

    def get_status(self):
        if not self.plan:
            return 'none'
        if self.end_date and self.end_date < now().date():
            return 'expired'
        return 'active'

    restaurant = models.OneToOneField(Restaurant, on_delete=models.CASCADE, related_name='subscription', null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='subscriptions')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.SET_NULL, null=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='none')

    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)

    history = HistoricalRecords()

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
        ('pending', 'Pending')
    ]

    subscription = models.ForeignKey(Subscription, on_delete=models.CASCADE, related_name='invoices')

    date = models.DateField(auto_now_add=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    plan_name = models.CharField(max_length=50)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    history = HistoricalRecords()

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




