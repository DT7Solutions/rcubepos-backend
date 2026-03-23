from rest_framework import serializers
from django.contrib.auth import authenticate
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
    password = serializers.CharField(write_only=True)

    class Meta:
        model = Users
        fields = [
            'first_name',
            'last_name',
            'username',
            'email',
            'phone',
            'password',
        ]

    def create(self, validated_data):
        password = validated_data.pop('password')

        user = Users.objects.create(**validated_data)

        try:
            owner_role = Role.objects.get(role_category='owner')
            user.role = owner_role
        except Role.DoesNotExist:
            raise serializers.ValidationError("Owner role does not exist. Please create it before registering users.")
        
        user.set_password(password)
        user.save()

        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

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

class ChangePasswordSerializer(serializers.Serializer):
    current = serializers.CharField()
    new_password = serializers.CharField()

    def validate(self, data):
        user = self.context['request'].user

        if not user.check_password(data['current']):
            raise serializers.ValidationError("Current password is incorrect")

        return data

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

# ======================== # ADMIN USER SERIALIZER # =========================
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
            "date_joined",
            "is_active",
        ]

    def get_restaurant_name(self, obj):
        restaurant = Restaurant.objects.filter(owner=obj).first()
        return restaurant.name if restaurant else None

# ========================= # RESTAURANT SERIALIZER # =========================
class RestaurantSerializer(serializers.ModelSerializer):
    owner_name = serializers.CharField(source='owner.username', read_only=True)
    owner_email = serializers.CharField(source='owner.email', read_only=True)

    plan = serializers.SerializerMethodField()
    expiry_date = serializers.SerializerMethodField()

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
        ]

    def get_plan(self, obj):
        if hasattr(obj, 'subscription') and obj.subscription.plan:
            return obj.subscription.plan.name
        return "Free"

    def get_expiry_date(self, obj):
        if hasattr(obj, 'subscription') and obj.subscription.end_date:
            return obj.subscription.end_date
        return None
    
# ========================= # SUBSCRIPTION SERIALIZER # =========================
class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ['id', 'date', 'amount', 'plan_name', 'status']

class OwnerSubscriptionSerializer(serializers.ModelSerializer):
    plan_id = serializers.IntegerField(source='plan.id', read_only=True)
    plan_name = serializers.CharField(source='plan.name', read_only=True)

    invoices = InvoiceSerializer(many=True, read_only=True)

    class Meta:
        model = Subscription
        fields = [
            'status',
            'plan_id',
            'plan_name',
            'start_date',
            'end_date',
            'invoices',
        ]

class ChangePlanSerializer(serializers.Serializer):
    plan_id = serializers.IntegerField()

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = [
            'id',
            'name',
            'price',
            'interval',
            'features',
            'popular',
            'is_active',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_price(self, value):
        if value < 0:
            raise serializers.ValidationError("Price cannot be negative.")
        return value

    def validate_interval(self, value):
        if value not in ['monthly', 'yearly']:
            raise serializers.ValidationError("Invalid interval. Must be 'monthly' or 'yearly'.")
        return value

    def validate_features(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Features must be a list.")
        
        if not all(isinstance(feature, str) and feature.strip() for feature in value):
            raise serializers.ValidationError("Each feature must be a non-empty string.")
        
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

# ========================= # PLATFORM SERIALIZER # =========================
class PlatformSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PlatformSettings
        fields = ['gst_percent', 'currency']