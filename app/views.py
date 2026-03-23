from rest_framework import status, viewsets, permissions, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, ValidationError

from django.contrib.auth import authenticate
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from drf_yasg.utils import swagger_auto_schema

from django.utils.timezone import now
from datetime import timedelta

from .models import *
from .serializers import *

# Create your views here.

# ========================= # AUTH VIEWS # =========================
def get_tokens_for_user(user):

    refresh = RefreshToken.for_user(user)
    return {
        'access_token': str(refresh.access_token),  # matches frontend
        'refresh_token': str(refresh),
    }

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=RegisterSerializer)
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()
        token_data = get_tokens_for_user(user)

        response = Response({
            "access_token": token_data["access_token"],
            "user": UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)

        response.set_cookie(
            key='refresh_token',
            value=token_data["refresh_token"],
            httponly=True,
            secure=True,
            samesite='None',
        )

        return response
    
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=LoginSerializer)
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        token_data = get_tokens_for_user(user)

        response = Response({
            "access_token": token_data["access_token"],
            "user": UserSerializer(user).data
        })

        response.set_cookie(
            key='refresh_token',
            value=token_data["refresh_token"],
            httponly=True,
            secure=True,
            samesite='None',
        )

        return response

class RefreshTokenView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response({"message": "No refresh token"}, status=401)

        try:
            refresh = RefreshToken(refresh_token)
            new_access = str(refresh.access_token)

            return Response({
                "access_token": new_access
            })

        except TokenError:
            return Response({"message": "Invalid refresh token"}, status=401)

class ProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)

    @swagger_auto_schema(request_body=ProfileUpdateSerializer)
    def patch(self, request):
        serializer = ProfileUpdateSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(UserSerializer(request.user).data)

class ChangePasswordView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(request_body=ChangePasswordSerializer)
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"message": "Password updated successfully"})
    
class ForgotPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=ForgotPasswordSerializer)
    def post(self, request):
        email = request.data.get("email")
        return Response({
            "message": f"Password reset link sent to {email}"
        })
    
# ========================= # ADMIN VIEWS # =========================
class AdminUserViewSet(viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = AdminUserSerializer

    def get_queryset(self):
        if not self.request.user.is_staff:
            raise PermissionDenied("Only admin can access users.")

        return User.objects.filter(is_staff=False)

    # ================= CREATE =================
    def create(self, request):
        if not request.user.is_staff:
            raise PermissionDenied("Only admin can create users.")

        email = request.data.get("email")
        password = request.data.get("password", "Temp@123")
        name = request.data.get("name")
        phone = request.data.get("phone")
        restaurant_name = request.data.get("restaurant")

        if not email or not name:
            raise ValidationError("Name and email are required.")

        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            first_name=name,
        )

        # Optional phone
        if phone:
            user.phone = phone
            user.save()

        # Create restaurant
        if restaurant_name:
            Restaurant.objects.create(
                name=restaurant_name,
                owner=user
            )

        return Response(AdminUserSerializer(user).data, status=201)

    # ================= SOFT DELETE =================
    def destroy(self, request, *args, **kwargs):
        if not request.user.is_staff:
            raise PermissionDenied("Only admin can delete users.")

        user = self.get_object()
        user.is_active = False
        user.save()

        return Response({"message": "User deactivated"})
    
    @action(detail=True, methods=['post'])
    def reset_password(self, request, pk=None):
        if not request.user.is_staff:
            raise PermissionDenied("Only admin can reset passwords.")

        user = self.get_object()

        new_password = "Temp@123"  # or generate random

        user.set_password(new_password)
        user.save()

        return Response({
            "message": "Password reset successfully",
            "temporary_password": new_password
        })
        
# ========================= # RESTAURANT VIEWS # =========================
class RestaurantViewSet(viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = RestaurantSerializer

    # ================= QUERYSET =================
    def get_queryset(self):
        user = self.request.user

        queryset = Restaurant.objects.filter(is_deleted=False)

        # Admin → all restaurants
        if user.is_staff:
            return queryset

        # Owner → only their restaurants
        return queryset.filter(owner=user)

    # ================= CREATE =================
    def perform_create(self, serializer):
        restaurant = serializer.save(owner=self.request.user)

        # Attach subscription to restaurant
        sub = Subscription.objects.filter(user = self.request.user).first()
        
        if sub:
            sub.restaurant = restaurant
            sub.save()

    # ================= TOGGLE STATUS =================
    @action(detail=True, methods=['patch'])
    def toggle_status(self, request, pk=None):
        restaurant = self.get_object()

        if not request.user.is_staff and restaurant.owner != request.user:
            raise PermissionDenied("You don't have permission to change the status of this restaurant")

        restaurant.status = (
            'Inactive' if restaurant.status == 'Active' else 'Active'
        )
        restaurant.save()

        return Response(RestaurantSerializer(restaurant).data)
    
    # ================= CHANGE PLAN =================
    @swagger_auto_schema(request_body=ChangePlanSerializer)
    @action(detail=True, methods=['patch'])
    def change_plan(self, request, pk=None):
        restaurant = self.get_object()

        # Only admin allowed to change plans, not owners
        if not request.user.is_staff:
            raise PermissionDenied("Only admin can change plans.")

        plan_id = request.data.get('plan_id')

        if not plan_id:
            raise ValidationError({"plan_id": "This field is required."})
        
        try:
            plan = SubscriptionPlan.objects.get(id=plan_id)
        except SubscriptionPlan.DoesNotExist:
            raise ValidationError({"plan_id": "Invalid plan ID."})

        sub, created = Subscription.objects.get_or_create(restaurant=restaurant)

        sub.plan = plan
        sub.status = 'active'
        sub.start_date = now().date()

        if plan.interval == 'monthly':
            sub.end_date = sub.start_date + timedelta(days=30)
        elif plan.interval == 'yearly':
            sub.end_date = sub.start_date + timedelta(days=365)

        sub.save()

        return Response(
            {
                "message": "Plan updated successfully.",
                "restaurant": RestaurantSerializer(restaurant).data
            }
        )

    # ================= GET SUBSCRIPTION =================
    @action(detail=True, methods=['get'])
    def subscription(self, request, pk=None):
        restaurant = self.get_object()

        sub, _ = Subscription.objects.get_or_create(restaurant=restaurant)

        return Response(OwnerSubscriptionSerializer(sub).data)
    
# ========================= # SUBSCRIPTION VIEWS # =========================
class MySubscriptionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sub = Subscription.objects.filter(user=request.user).first()

        if not sub:
            return Response({
                "status": "none",
                "plan": None,
                "start_date": None,
                "end_date": None
            })
        
        status = sub.get_status()

        if status != sub.status:
            sub.status = status
            sub.save(update_fields=['status'])        

        return Response({
            "status": status,
            "plan": {
                "id": sub.plan.id if sub.plan else None,
                "name": sub.plan.name if sub.plan else None,
            },
            "start_date": sub.start_date,
            "end_date": sub.end_date,
        })

class SubscriptionPlanViewSet(viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = SubscriptionPlanSerializer

    def get_queryset(self):
        user = self.request.user

        # Admin → all plans
        if user.is_staff:
            return SubscriptionPlan.objects.all()

        # Owner → only active plans
        return SubscriptionPlan.objects.filter(is_active=True)
    
    # ================= PERMISSIONS =================
    def perform_create(self, serializer):
        if not self.request.user.is_staff:
            raise PermissionDenied("Only admin can create plans.")
        serializer.save()

    def perform_update(self, serializer):
        if not self.request.user.is_staff:
            raise PermissionDenied("Only admin can update plans.")
        serializer.save()

    def perform_destroy(self, instance):
        if not self.request.user.is_staff:
            raise PermissionDenied("Only admin can delete plans.")

        # Soft delete instead of actual delete
        instance.is_active = False
        instance.save()

class SelectPlanView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(request_body=ChangePlanSerializer)
    def post(self, request):
        user = request.user

        plan_id = request.data.get("plan_id")

        if not plan_id:
            return Response({"error": "plan_id is required"}, status=400)

        try:
            plan = SubscriptionPlan.objects.get(id=plan_id, is_active=True)
        except SubscriptionPlan.DoesNotExist:
            return Response({"error": "Invalid plan"}, status=400)

        # Get or create subscription for user
        sub, _ = Subscription.objects.get_or_create(user=user)

        sub.plan = plan
        sub.status = "active"
        sub.start_date = now().date()

        # duration
        if plan.interval == "monthly":
            sub.end_date = sub.start_date + timedelta(days=30)
        elif plan.interval == "yearly":
            sub.end_date = sub.start_date + timedelta(days=365)

        sub.save()

        return Response({
            "message": "Plan selected successfully",
            "plan": plan.name,
            "end_date": sub.end_date
        })

# ========================= # PLATFORM VIEWS # =========================
class PlatformSettingsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        settings = PlatformSettings.objects.first()
        serializer = PlatformSettingsSerializer(settings)
        return Response(serializer.data)
    



    