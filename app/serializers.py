from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from .models import *

# ========================= # ROLE SERIALIZER # =========================
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'role_name', 'role_category']

# ========================= # USER SERIALIZER # =========================
class UserSerializer(serializers.ModelSerializer):
    role = RoleSerializer(read_only=True)

    class Meta:
        model = Users
        fields = [
            'id',
            'first_name',
            'last_name',
            'username',
            'email',
            'phone',
            'profile_image',
            'role',
        ]

# ========================= # AUTH SERIALIZER # =========================
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    phone_country_code = serializers.CharField(required=True)
    billing_country = serializers.CharField(required=True)

    class Meta:
        model = Users
        fields = [
            'first_name',
            'last_name',
            'username',
            'email',
            'phone',
            'phone_country_code',
            'billing_country',
            'password',
        ]

    def validate_password(self, value):
        """Validate password strength using Django's built-in validators."""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate_username(self, value):
        if Users.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value

    def validate_email(self, value):
        if Users.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value

    def validate_phone(self, value):
        if Users.objects.filter(phone=value).exists():
            raise serializers.ValidationError("Phone number already exists")
        return value
    
    def validate_phone_country_code(self, value):
        if not value.startswith("+"):
            raise serializers.ValidationError("Country code must start with '+'")
        return value
    
    def validate_billing_country(self, value):
        if len(value) != 2:
            raise serializers.ValidationError("Country must be ISO 2-letter code")
        return value.upper()

    def create(self, validated_data):
        password = validated_data.pop('password')

        phone_country_code = validated_data.pop('phone_country_code')
        billing_country = validated_data.pop('billing_country')

        user = Users.objects.create(**validated_data)

        try:
            owner_role = Role.objects.get(role_category='owner')
            user.role = owner_role
        except Role.DoesNotExist:
            raise serializers.ValidationError("Owner role does not exist. Please create it before registering users.")
        
        user.set_password(password)
        user.billing_country = billing_country
        user.phone_country_code = phone_country_code
        user.save()

        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=8)

    def validate(self, data):
        user = authenticate(
            email=data['email'],
            password=data['password']
        )

        if not user:
            raise serializers.ValidationError("Invalid credentials")

        data['user'] = user
        return data

class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['first_name', 'last_name', 'email', 'phone']

    def validate_email(self, value):
        """Check that email is not already used by another user."""
        if Users.objects.filter(email=value).exclude(pk=self.instance.pk).exists():
            raise serializers.ValidationError("Email already in use")
        return value

    def validate_phone(self, value):
        """Check that phone is not already used by another user."""
        if value and Users.objects.filter(phone=value).exclude(pk=self.instance.pk).exists():
            raise serializers.ValidationError("Phone number already in use")
        return value

class ChangePasswordSerializer(serializers.Serializer):
    current = serializers.CharField()
    new_password = serializers.CharField(min_length=8, required=True)
    confirm_password = serializers.CharField(min_length=8, required=True)

    def validate_new_password(self, value):
        """Validate new password strength."""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError("New password is too weak: " + ', '.join(e.messages))
        return value

    def validate(self, data):
        user = self.context['request'].user

        if not user.check_password(data['current']):
            raise serializers.ValidationError("The current password you entered is incorrect.")
        
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("The new password and confirmation password do not match.")

        return data

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

# ======================== # ADMIN USER SERIALIZER # =========================
User = get_user_model()
class AdminUserSerializer(serializers.ModelSerializer):
    restaurant_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "email",
            "phone",
            "restaurant_name",
            "created_at",
            "is_active",
        ]

    def get_restaurant_name(self, obj):
        restaurant = Restaurant.objects.filter(owner=obj).first()
        return restaurant.name if restaurant else None

class AdminTransactionSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source="user.username", read_only=True)
    user_email = serializers.CharField(source="user.email", read_only=True)

    final_amount = serializers.FloatField()
    restaurant_name = serializers.SerializerMethodField()

    class Meta:
        model = PaymentTransaction
        fields = [
            "id",
            "transaction_id",
            "stripe_payment_intent_id",
            "user_name",
            "user_email",
            "restaurant_name",
            "final_amount",
            "currency",
            "payment_method",
            "status",
            "created_at",
            "paid_at",
        ]

    def get_restaurant_name(self, obj):
        if obj.subscription and obj.subscription.restaurant:
            return obj.subscription.restaurant.name
        return None

# ========================= # RESTAURANT SERIALIZER # =========================
class RestaurantSerializer(serializers.ModelSerializer):
    owner_name = serializers.CharField(source='owner.username', read_only=True)
    owner_email = serializers.CharField(source='owner.email', read_only=True)

    plan = serializers.SerializerMethodField()
    expiry_date = serializers.SerializerMethodField()
    latest_invoice_id = serializers.SerializerMethodField()

    class Meta:
        model = Restaurant
        fields = [
            'id',
            'name',
            'owner_name',
            'owner_email',
            'phone',
            'address',
            'gst_number',
            'plan',
            'status',
            'created_at',
            'expiry_date',
            'latest_invoice_id',
        ]

    def get_plan(self, obj):
        if hasattr(obj, 'subscription') and obj.subscription.plan:
            return obj.subscription.plan.name
        return "Free"

    def get_expiry_date(self, obj):
        if hasattr(obj, 'subscription') and obj.subscription.end_date:
            return obj.subscription.end_date
        return None
        
    def get_latest_invoice_id(self, obj):
        if hasattr(obj, 'subscription') and obj.subscription:
            latest_invoice = obj.subscription.invoices.order_by('-created_at').first()
            return latest_invoice.id if latest_invoice else None
        return None
    
# ========================= # SUBSCRIPTION SERIALIZER # =========================
CURRENCY_SYMBOLS = {
    "INR": "₹",
    "USD": "$",
    "CAD": "$"
}

class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = [
            'id',
            'invoice_number',
            'subscription',
            'date',
            'base_amount',
            'discount_amount',
            'gst_amount',
            'total_amount',
            'currency',
            'plan_name',
            'plan_interval',
            'status'
        ]
        read_only_fields = ['id', 'date']

class OwnerSubscriptionSerializer(serializers.ModelSerializer):
    plan_id = serializers.IntegerField(source='plan.id', read_only=True)
    plan_name = serializers.CharField(source='plan.name', read_only=True)

    status = serializers.SerializerMethodField()
    is_active = serializers.SerializerMethodField()

    invoices = InvoiceSerializer(many=True, read_only=True)

    class Meta:
        model = Subscription
        fields = [
            'status',
            'is_active',
            'plan_id',
            'plan_name',
            'start_date',
            'end_date',
            'cancel_at_period_end',
            'cancel_at',
            'invoices',
        ]

    def get_status(self, obj):
        return obj.get_status()
    
    def get_is_active(self, obj):
        return obj.get_status() == 'active'

class ChangePlanSerializer(serializers.Serializer):
    plan_id = serializers.IntegerField()

    def validate_plan_id(self, value):
        """Validate that the plan exists."""
        if not SubscriptionPlan.objects.filter(id=value).exists():
            raise serializers.ValidationError("Subscription plan does not exist.")
        return value

class SubscriptionPlanSerializer(serializers.ModelSerializer):    
    price = serializers.SerializerMethodField()
    currency = serializers.SerializerMethodField()
    currency_symbol = serializers.SerializerMethodField()

    class Meta:
        model = SubscriptionPlan
        fields = [
            'id',
            'name',
            'price',
            'currency',
            'currency_symbol',
            'interval',
            'features',
            'popular',
            'is_active',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    # ============== PRICING HELPER METHODS ==============
    def _get_pricing(self, obj):
        return self.context.get("pricing_map", {}).get(obj.id)
    
    def get_price(self, obj):
        pricing = self._get_pricing(obj)
        return pricing.price if pricing else None
    
    def get_currency(self, obj):
        pricing = self._get_pricing(obj)
        return pricing.currency if pricing else "USD"
    
    def get_currency_symbol(self, obj):
        pricing = self._get_pricing(obj)
        currency = pricing.currency if pricing else "USD"
        return CURRENCY_SYMBOLS.get(currency, "$")

    # =============== Validations ===============
    def validate_interval(self, value):
        if value not in ['monthly', 'yearly']:
            raise serializers.ValidationError("Invalid interval. Must be 'monthly' or 'yearly'.")
        return value

    def validate_features(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Features must be a list.")

        if len(value) > 50:
            raise serializers.ValidationError("Maximum 50 features allowed.")

        if not all(isinstance(feature, str) and feature.strip() for feature in value):
            raise serializers.ValidationError("Each feature must be a non-empty string.")

        if any(len(feature) > 255 for feature in value):
            raise serializers.ValidationError("Feature names must be under 255 characters.")

        return value
    def validate(self, data):
        name = data.get("name", getattr(self.instance, "name", None))
        interval = data.get("interval", getattr(self.instance, "interval", None))

        qs = SubscriptionPlan.objects.filter(
            name=name,
            interval=interval
        )

        # Exclude self when updating
        if self.instance:
            qs = qs.exclude(id=self.instance.id)

        if qs.exists():
            raise serializers.ValidationError(
                "A plan with this name and interval already exists."
            )

        return data

class PlanPricingSerializer(serializers.ModelSerializer):
    class Meta:
        model = PlanPricing
        fields = [
            'id',
            'plan',
            'country',
            'currency',
            'price',
            'stripe_price_id',
            'is_active',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_country(self, value):
        if len(value) != 2:
            raise serializers.ValidationError(
                "Country must be ISO 2-letter code."
            )
        return value.upper()

    def validate_price(self, value):
        if value < 0:
            raise serializers.ValidationError("Price cannot be negative.")
        return value

# ========================= # PAYMENT SERIALIZER # =========================
class PaymentTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentTransaction
        fields = [
            'id',
            'transaction_id',
            'user',
            'subscription',
            'status',
            'base_amount',
            'discount_amount',
            'gst_amount',
            'final_amount',
            'refunded_amount',
            'payment_method',
            'currency',
            'stripe_session_id',
            'stripe_payment_intent_id',
            'created_at',
            'paid_at'
        ]
        read_only_fields = ['id', 'transaction_id', 'created_at', 'paid_at']

class RefundSerializer(serializers.ModelSerializer):
    class Meta:
        model = Refund
        fields = [
            'id',
            'payment_transaction',
            'amount',
            'reason',
            'stripe_refund_id',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at', 'stripe_refund_id']

# ========================= # PLATFORM SERIALIZER # =========================
class PlatformSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PlatformSettings
        fields = ['gst_percent', 'currency']

