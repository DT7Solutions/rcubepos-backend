from requests import session
from rest_framework import status, viewsets, permissions, generics 
from rest_framework.views import APIView, View
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework import status

from django.contrib.auth import authenticate
from django.conf import settings
from django.http import HttpResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from drf_yasg.utils import swagger_auto_schema

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from django.utils.timezone import now
from django.utils.dateparse import parse_date
from django.db import transaction
from django.db.models import Sum, Count
from django.db.models.functions import TruncMonth
from datetime import timedelta, timezone
# from collections import deafultdict
import logging
import stripe
import requests
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from ipware import get_client_ip
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from .models import *
from .serializers import *
from .utils import *
from .permissions import *

# Create your views here.

# ========================= # AUTH VIEWS # =========================

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    @csrf_exempt
    @swagger_auto_schema(request_body=RegisterSerializer)
    def post(self, request):
        """
        Register a new user with improved error handling.
        
        Handles:
        - Missing or invalid fields
        - Duplicate email/username
        - Database errors
        - Token generation errors
        """
        try:
            serializer = RegisterSerializer(data=request.data)
            
            if not serializer.is_valid():
                return Response(
                    {
                        "success": False,
                        "error": "Validation failed",
                        "details": serializer.errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = serializer.save()
            current_time = now()

            # Generate OTP
            otp_code = generate_otp()

            # Set Full OTP State
            user.otp = otp_code
            user.otp_created_at = current_time
            user.otp_last_sent_at = current_time
            user.is_email_verified = False
            user.otp_context = settings.OTP_CONTEXT_REGISTER
            user.otp_attempts = 0
            user.otp_blocked_until = None
            user.save()

            # Send OTP email
            try:
                send_otp_email(user.email, otp_code, context=settings.OTP_CONTEXT_REGISTER)

            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to send OTP email to {user.email}: {str(e)}", exc_info=True)
                return Response(
                    {
                        "success": False,
                        "error": "User created but failed to send OTP email",
                        "details": {"email": ["Failed to send OTP email"]},
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            return Response(
                {
                    "success": True,
                    "message": "User registered successfully. Please verify your email with the OTP sent.",
                    "user_id": user.id,
                    "email": user.email,
                    "action": "VERIFY_OTP"
                },
                status=status.HTTP_201_CREATED
            )

        except ValidationError as e:
            return Response(
                {
                    "success": False,
                    "error": "Validation error",
                    "details": e.detail if hasattr(e, 'detail') else {}
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            # Catch unexpected errors
            logger = logging.getLogger(__name__)
            logger.error(f"Unexpected error during registration: {str(e)}", exc_info=True)
            return Response(
                {
                    "success": False,
                    "error": "An unexpected error occurred during registration",
                    "details": {}
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    @csrf_exempt
    @swagger_auto_schema(request_body=LoginSerializer)
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {
                        "error": "Invalid credentials",
                        "details": serializer.errors
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = serializer.validated_data.get('user')

            if not user:
                return Response(
                    {
                        "error": "Invalid email or password",
                        "details": {}
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Account inactive
            if not user.is_active:
                return Response(
                    {
                        "error": "Account is deactivated",
                        "details": {"account": ["Your account has been disabled"]}
                    },
                    status=status.HTTP_403_FORBIDDEN
                )

            current_time = now()

            # EMAIL NOT VERIFIED → TRIGGER OTP FLOW
            if not user.is_email_verified:

                with transaction.atomic():
                    user = Users.objects.select_for_update().get(id=user.id)

                    # Block check
                    block_response = check_otp_blocked(user, current_time)
                    if block_response:
                        return block_response

                    # Cooldown check
                    cooldown_response = check_otp_cooldown(user, current_time)
                    if cooldown_response:
                        return cooldown_response

                    # Generate OTP
                    otp_code = generate_otp()

                    user.otp = otp_code
                    user.otp_created_at = current_time
                    user.otp_last_sent_at = current_time
                    user.otp_context = settings.OTP_CONTEXT_REGISTER

                    user.save()

                # Send OTP (outside transaction)
                try:
                    send_otp_email(user.email, otp_code, context=settings.OTP_CONTEXT_REGISTER)
                except Exception as e:
                    logger = logging.getLogger(__name__)
                    logger.error(f"Failed to send OTP email to {user.email}: {str(e)}", exc_info=True)
                    return Response(
                        {
                            "success": False,
                            "error": "Failed to send OTP email",
                            "details": {"email": ["Failed to send OTP email"]}
                        },
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

                return Response(
                    {
                        "success": False,
                        "error": "Email not verified",
                        "message": "OTP sent to your email. Please verify to continue.",
                        "email": user.email,
                        "code": "EMAIL_NOT_VERIFIED",
                        "action": "VERIFY_OTP"
                    },
                    status=status.HTTP_403_FORBIDDEN
                )

            # VERIFIED USER → NORMAL LOGIN

            try:
                token_data = get_tokens_for_user(user)
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Token generation failed for user {user.id}: {str(e)}", exc_info=True)
                return Response(
                    {
                        "error": "Failed to generate authentication tokens",
                        "details": {}
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            if not token_data.get("access_token"):
                return Response(
                    {
                        "error": "Authentication token generation failed",
                        "details": {}
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            response = Response(
                {
                    "success": True,
                    "message": "Login successful",
                    "access_token": token_data["access_token"],
                    "user": UserSerializer(user).data
                },
                status=status.HTTP_200_OK
            )

            response.set_cookie(
                key='refresh_token',
                value=token_data["refresh_token"],
                httponly=True,
                secure=True,
                samesite='None',
            )

            return response

        except ValidationError as e:
            return Response(
                {
                    "error": "Validation error",
                    "details": e.detail if hasattr(e, 'detail') else {}
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "success": False,
                    "error": "An unexpected error occurred during login",
                    "details": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        if not email or not otp:
            return Response({
                "success": False,
                "error": "Email and OTP are required"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate OTP format (should be numeric and correct length)
        if not otp.isdigit() or len(otp) != settings.OTP_LENGTH:
            return Response({
                "success": False,
                "error": f"OTP must be {settings.OTP_LENGTH} digits"
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return Response({
                "success": False,
                "error": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)

        current_time = now()

        # BLOCK CHECK
        block_response = check_otp_blocked(user, current_time)
        if block_response:
            return block_response

        # EXPIRY CHECK
        expiry_response = check_otp_expired(user, current_time)
        if expiry_response:
            return expiry_response

        # INVALID OTP - Atomic update to prevent race conditions
        if user.otp != otp:
            with transaction.atomic():
                # Re-fetch with lock to prevent concurrent modifications
                user = Users.objects.select_for_update().get(id=user.id)

                user.otp_attempts += 1
                if user.otp_attempts >= settings.OTP_MAX_ATTEMPTS:
                    user.otp_blocked_until = current_time + timedelta(hours=settings.OTP_BLOCK_DURATION_HOURS)

                user.save()

            return Response({
                "success": False,
                "error": "Invalid OTP",
                "attempts_remaining": max(0, settings.OTP_MAX_ATTEMPTS - user.otp_attempts)
            }, status=status.HTTP_400_BAD_REQUEST)

        # CONTEXT CHECK (ONLY ON SUCCESS)
        context = user.otp_context

        if not context:
            return Response({
                "success": False,
                "error": "OTP context missing. Please request OTP again.",
                "code": "OTP_CONTEXT_MISSING"
            }, status=status.HTTP_400_BAD_REQUEST)

        # =============================
        # CONTEXT HANDLING
        # =============================

        if context == settings.OTP_CONTEXT_REGISTER:
            user.is_email_verified = True

            try:
                token_data = get_tokens_for_user(user)
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Token generation failed for user {user.id}: {str(e)}", exc_info=True)
                return Response({
                    "success": False,
                    "error": "Verification successful but login failed"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # RESET STATE
            reset_otp_fields(user, full_reset=True)
            user.save()

            response = Response({
                "success": True,
                "message": "Email verified successfully",
                "access_token": token_data["access_token"],
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username
                }
            }, status=status.HTTP_200_OK)

            response.set_cookie(
                key='refresh_token',
                value=token_data["refresh_token"],
                httponly=True,
                secure=True,
                samesite='None',
            )

            return response

        elif context == settings.OTP_CONTEXT_CHANGE_PASSWORD:
            reset_otp_fields(user, full_reset=False)
            user.save()

            return Response({
                "success": True,
                "message": "OTP verified. You can now reset your password."
            }, status=status.HTTP_200_OK)

        elif context == settings.OTP_CONTEXT_CHANGE_EMAIL_OLD:
            reset_otp_fields(user, full_reset=False)
            user.save()

            return Response({
                "success": True,
                "message": "Current email verified. Proceed to verify new email."
            }, status=status.HTTP_200_OK)

        elif context == settings.OTP_CONTEXT_CHANGE_EMAIL_NEW:
            if not user.pending_email:
                return Response({
                    "success": False,
                    "error": "No pending email found"
                }, status=status.HTTP_400_BAD_REQUEST)

            user.email = user.pending_email
            user.pending_email = None

            reset_otp_fields(user, full_reset=False)
            user.save()

            return Response({
                "success": True,
                "message": "Email updated successfully",
                "email": user.email
            }, status=status.HTTP_200_OK)

        # UNKNOWN CONTEXT
        return Response({
            "success": False,
            "error": "Invalid OTP context",
            "code": "INVALID_CONTEXT"
        }, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response(
                {
                    "success": False,
                    "error": "Email is required"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            with transaction.atomic():
                user = Users.objects.select_for_update().get(email=email)

                current_time = now()

                # BLOCK CHECK
                block_response = check_otp_blocked(user, current_time)
                if block_response:
                    return block_response

                # COOLDOWN CHECK
                cooldown_response = check_otp_cooldown(user, current_time)
                if cooldown_response:
                    return cooldown_response

                # CONTEXT CHECK
                if not user.otp_context:
                    return Response(
                        {
                            "success": False,
                            "error": "No active OTP request found"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # GENERATE NEW OTP
                new_otp = generate_otp()

                user.otp = new_otp
                user.otp_created_at = current_time
                user.otp_last_sent_at = current_time
                # ❗ DO NOT reset otp_attempts (prevents brute force bypass)

                user.save()

            # SEND EMAIL (outside transaction)
            try:
                send_otp_email(user.email, new_otp, context=user.otp_context)
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to send OTP email to {user.email}: {str(e)}", exc_info=True)
                return Response(
                    {
                        "success": False,
                        "error": "Failed to send OTP email",
                        "details": {"email": [str(e)]}
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {
                    "success": True,
                    "message": "OTP resent successfully",
                    "email": user.email
                },
                status=status.HTTP_200_OK
            )

        except Users.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "error": "User not found"
                },
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Unexpected error in resend OTP for {email}: {str(e)}", exc_info=True)
            return Response(
                {
                    "success": False,
                    "error": "Something went wrong"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CheckAvailabilityView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        field = request.data.get("field")
        value = request.data.get("value")

        # Validate field name - only allow safe field names
        allowed_fields = ["email", "username", "phone"]
        if field not in allowed_fields:
            return Response(
                {"error": "Invalid field"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate value is provided and has reasonable length
        if not value:
            return Response(
                {"error": f"{field} is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if len(str(value)) > 255:
            return Response(
                {"error": f"{field} is too long"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Safe to use field name since we validated it above
        exists = Users.objects.filter(**{field: value}).exists()

        return Response({
            "field": field,
            "available": not exists
        }, status=status.HTTP_200_OK)

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
            email=email,
            username=email,
            phone=phone or "",
            password=password,
        )
        user.first_name = name
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

class AdminTransactionListView(ListAPIView):

    class TransactionPagination(PageNumberPagination):
        page_size = 20
        page_size_query_param = 'page_size'

    serializer_class = AdminTransactionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = TransactionPagination

    def get_queryset(self):
        user = self.request.user

        if not user.is_staff:
            raise PermissionDenied("Admin only")

        queryset = PaymentTransaction.objects.select_related(
            "user",
            "subscription__restaurant"
        ).order_by("-created_at")

        # Optional filters (very useful)
        status = self.request.query_params.get("status")
        if status:
            queryset = queryset.filter(status=status)

        start_date = self.request.query_params.get("start_date")
        
        if start_date:
            queryset = queryset.filter(created_at__date__gte=parse_date(start_date))

        end_date = self.request.query_params.get("end_date")
        if end_date:
            queryset = queryset.filter(created_at__date__lte=parse_date(end_date))

        return queryset

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
        sub = Subscription.objects.filter(user=self.request.user).first()
        
        if sub and not sub.restaurant:
            sub.restaurant = restaurant
            sub.save()

    # ================= UPDATE & DELETE PERMISSIONS =================
    def get_permissions(self):
        user = self.request.user

        if user.is_staff:
            return [IsAuthenticated()]

        if self.action in ['list', 'retrieve', 'create']:
            return [IsAuthenticated()]
        return [IsAuthenticated(), IsSubscriptionActive()]

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

        sub, created = Subscription.objects.get_or_create(
            restaurant=restaurant,
            defaults={'user': restaurant.owner}
        )

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

# ========================= # DASHBOARD VIEWS # =========================
class AdminDashboardView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_staff:
            raise PermissionDenied("Admin only")

        # ================= CARDS =================
        total_restaurants = Restaurant.objects.filter(is_deleted=False).count()

        active_restaurants = Restaurant.objects.filter(
            is_deleted=False,
            status="Active"
        ).count()

        payments = PaymentTransaction.objects.filter(status="success")

        total_revenue = payments.aggregate(
            total=Sum("final_amount")
        )["total"] or 0

        # ================= CHART =================
        monthly_data = payments.annotate(
            month=TruncMonth("created_at")
        ).values("month").annotate(
            revenue=Sum("final_amount")
        ).order_by("month")

        # Format for frontend
        revenue_chart = [
            {
                "month": entry["month"].strftime("%b"),
                "revenue": entry["revenue"]
            }
            for entry in monthly_data if entry["month"]
        ]

        return Response({
            "cards": {
                "total_restaurants": total_restaurants,
                "active_restaurants": active_restaurants,
                "total_revenue": total_revenue
            },
            "revenue_chart": revenue_chart
        })

class OwnerDashboardView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        sub = Subscription.objects.filter(user=user)\
            .select_related("plan")\
            .prefetch_related("invoices")\
            .first()

        payments = PaymentTransaction.objects.filter(
            user=user,
            status="success"
        )

        total_spent = payments.aggregate(
            total=Sum("final_amount")
        )["total"] or 0

        return Response({
            "subscription": OwnerSubscriptionSerializer(sub).data if sub else None,
            "total_spent": total_spent,
            "payments": PaymentTransactionSerializer(
                payments.order_by("-created_at")[:5],
                many=True
            ).data
        })

# ========================= # SUBSCRIPTION VIEWS # =========================

class MySubscriptionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        sub = Subscription.objects.filter(user=user)\
            .select_related('plan', 'restaurant')\
            .prefetch_related('invoices')\
            .first()

        if not sub:
            return Response({
                "status": "none",
                "plan": None,
                "start_date": None,
                "end_date": None,
                "invoices": [],
                "payments": []
            })

        # Sync status if stale
        derived_status = sub.get_status()
        if derived_status != sub.status:
            Subscription.objects.filter(id=sub.id).update(status=derived_status)

        # Fetch ALL transactions for this user (all statuses)
        payments = PaymentTransaction.objects.filter(
            user=user
        ).order_by("-created_at")

        sub_data = OwnerSubscriptionSerializer(sub).data
        sub_data["payments"] = PaymentTransactionSerializer(payments, many=True).data

        return Response(sub_data)

class SubscriptionPlanViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.AllowAny]
    serializer_class = SubscriptionPlanSerializer

    def get_queryset(self):
        user = self.request.user

        # Admin → all plans
        if user.is_staff:
            return SubscriptionPlan.objects.all()

        # Owner → only active plans
        return SubscriptionPlan.objects.filter(is_active=True)
        
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        user = request.user

        # ================= COUNTRY LOGIC =================
        country = "US" # initial default
        
        if user.is_authenticated and hasattr(user, 'billing_country') and user.billing_country:
            country = user.billing_country
        else:
            ip_data = get_client_ip(request)
            client_ip = ip_data[0] if isinstance(ip_data, tuple) else ip_data
            
            if client_ip:
                cached_country = cache.get(f"ip_country_{client_ip}")
                if cached_country:
                    country = cached_country
                else:
                    try:
                        response = requests.get(f"http://ip-api.com/json/{client_ip}?fields=countryCode", timeout=3)
                        if response.status_code == 200:
                            data = response.json()
                            if data and data.get("countryCode"):
                                country = data["countryCode"]
                                cache.set(f"ip_country_{client_ip}", country, 86400) # 24 hours
                    except Exception as e:
                        logger = logging.getLogger(__name__)
                        logger.error(f"IP Geolocation failed for {client_ip}: {str(e)}")

        if country not in ["IN", "CA", "US"]:
            country = "US"  # final fallback

        # ================= PRICING =================
        pricing_qs = PlanPricing.objects.filter(country=country, is_active=True)
        pricing_map = {p.plan_id: p for p in pricing_qs}

        # fallback pricing for plans that don't have country-specific pricing
        missing_ids = set(queryset.values_list('id', flat=True)) - set(pricing_map.keys())

        if missing_ids:
            # fetch generic fallback or minimum price available 
            fallback_qs = PlanPricing.objects.filter(
                plan_id__in=missing_ids,
                is_active=True
            ).order_by('price') # pick one basically by sorting

            # pick the first one
            for p in fallback_qs:
                if p.plan_id not in pricing_map:
                    pricing_map[p.plan_id] = p

        serializer = self.get_serializer(queryset, many=True, context={'pricing_map': pricing_map, 'country': country})
        
        return Response({
            "country": country,
            "plans": serializer.data
        })

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

class PlanPricingViewSet(viewsets.ModelViewSet):
    queryset = PlanPricing.objects.all()
    serializer_class = PlanPricingSerializer

    def get_queryset(self):
        plan_id = self.request.query_params.get("plan")

        qs = PlanPricing.objects.all()

        if plan_id:
            qs = qs.filter(plan_id=plan_id)

        return qs

    def perform_create(self, serializer):
        if not self.request.user.is_staff:
            raise PermissionDenied("Admin only")
        serializer.save()

    def perform_update(self, serializer):
        if not self.request.user.is_staff:
            raise PermissionDenied("Admin only")
        serializer.save()

    def perform_destroy(self, instance):
        if not self.request.user.is_staff:
            raise PermissionDenied("Admin only")
        instance.delete()

class CreateCheckoutSessionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        plan_id = request.data.get("plan_id")

        if not plan_id:
            return Response({"error": "plan_id is required"}, status=400)

        try:
            plan = SubscriptionPlan.objects.get(id=plan_id, is_active=True)
        except SubscriptionPlan.DoesNotExist:
            return Response({"error": "Invalid plan"}, status=400)

        sub, _ = Subscription.objects.get_or_create(user=user)

        if sub.status == "active":
            return Response({"error": "You already have an active subscription"}, status=400)

        # ================= GET COUNTRY =================
        country = user.billing_country if user.billing_country else "US"

        # ================= GET PRICING =================
        pricing = get_plan_pricing(plan, country)

        if not pricing:
            return Response({"error": "Pricing not available for this country"}, status=400)

        # ================= CREATE PAYMENT =================
        payment = PaymentTransaction.objects.create(
            user=user,
            subscription=sub,
            base_amount=pricing.price,
            currency=pricing.currency,
            country=pricing.country,
            status='initiated',
        )

        # ================= STRIPE SESSION =================
        session = create_checkout_session(
            user=user,
            plan=plan,
            pricing=pricing  # IMPORTANT
        )

        payment.stripe_session_id = session.id
        payment.save()

        sub.last_session_created_at = now()
        sub.save(update_fields=["last_session_created_at"])

        return Response({
            "url": session.url,
            "session_id": session.id,
            "country": pricing.country,
            "currency": pricing.currency
        })

# Implement Webhook Later
class StripeWebhookView(APIView):
    permission_classes = [AllowAny]  # AllowAny (no auth)

    def post(self, request):
        payload = request.body
        sig_header = request.META.get("HTTP_STRIPE_SIGNATURE")

        try:
            event = stripe.Webhook.construct_event(
                payload,
                sig_header,
                settings.STRIPE_WEBHOOK_SECRET
            )
        except stripe.error.SignatureVerificationError:
            return JsonResponse({"error": "Invalid signature"}, status=400)
        except Exception:
            return JsonResponse({"error": "Invalid payload"}, status=400)
        
        event_id = event.get("id")

        if StripeWebhookLog.objects.filter(event_id=event_id).exists():
            return JsonResponse({"status": "already processed"}, status=200)

        # Handle only relevant event
        if event["type"] == "checkout.session.completed":
            session = event["data"]["object"]
            self.handle_successful_payment(session)
            StripeWebhookLog.objects.create(event_id=event_id, event_type=event["type"], payload=event, processed=True)

        return JsonResponse({"status": "success"})

    # Combined logic
    def handle_successful_payment(self, session):
        session_id = session.get("id")
        payment_intent = session.get("payment_intent")

        metadata = session.get("metadata", {})
        plan_id = metadata.get("plan_id")
        user_id = metadata.get("user_id")

        if not session_id or not payment_intent:
            return

        try:
            plan = SubscriptionPlan.objects.get(id=plan_id)
        except SubscriptionPlan.DoesNotExist:
            return

        with transaction.atomic():
            try:
                payment = PaymentTransaction.objects.select_for_update().get(stripe_session_id=session_id)
            except PaymentTransaction.DoesNotExist:
                return

            sub = payment.subscription

            # Idempotency
            if payment.status == "success":
                return

            # Safety check
            if str(user_id) != str(sub.user_id):
                return
            
            # Update Payment
            try:
                intent = stripe.PaymentIntent.retrieve(payment_intent)
            except Exception:
                return

            if intent.charges and intent.charges.data:
                charge = intent.charges.data[0]
                payment_method = charge.payment_method_details.type if charge.payment_method_details else "unknown"

            payment.stripe_payment_intent_id = payment_intent
            payment.payment_method = payment_method
            payment.status = "success"
            payment.paid_at = now()
            payment.save()

            # Activate subscription
            sub.plan = plan
            sub.status = "active"
            sub.start_date = now().date()

            if plan.interval == "monthly":
                sub.end_date = sub.start_date + timedelta(days=30)
            else:
                sub.end_date = sub.start_date + timedelta(days=365)

            sub.last_payment = payment
            sub.save()

            # Create invoice
            Invoice.objects.create(
                subscription=sub,
                payment=payment,
                base_amount=payment.base_amount,
                discount_amount=payment.discount_amount,
                gst_amount=payment.gst_amount,
                total_amount=payment.final_amount,
                currency=payment.currency,
                plan_name=plan.name,
                plan_interval=plan.interval,
                stripe_payment_intent_id=payment_intent,
                status='paid',
                invoice_number = f"INV-{payment.id}-{int(now().timestamp())}"
            )

# Fallback if Webhook Fails
@method_decorator(csrf_exempt, name='dispatch')
class VerifyPaymentView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        session_id = request.data.get("session_id")

        if not session_id:
            return Response({"error": "session_id required"}, status=400)

        try:
            session = stripe.checkout.Session.retrieve(session_id)
        except Exception:
            return Response({"error": "Invalid session"}, status=400)

        if session.payment_status != "paid":
            return Response({"error": "Payment not completed"}, status=400)

        if not session.payment_intent:
            return Response({"error": "Payment intent not found"}, status=400)

        # FIXED metadata handling
        metadata = session.metadata if session.metadata else {}

        plan_id = getattr(metadata, "plan_id", None)
        user_id = getattr(metadata, "user_id", None)

        # plan_id = metadata.plan_id if hasattr(metadata, 'plan_id') else metadata.get("plan_id")
        # plan_id = metadata.get("plan_id")
        # plan_id = metadata["plan_id"] if "plan_id" in metadata else None
        # user_id = metadata.user_id if hasattr(metadata, 'user_id') else metadata.get("user_id")
        # user_id = metadata.get("user_id")
        # user_id = metadata["user_id"] if "user_id" in metadata else None

        if not plan_id or not user_id:
            return Response({"error": "Invalid metadata"}, status=400)
        
        plan_id = int(plan_id)
        user_id = int(user_id)

        try:
            plan = SubscriptionPlan.objects.get(id=plan_id)
        except SubscriptionPlan.DoesNotExist:
            return Response({"error": "Plan not found"}, status=400)

        with transaction.atomic():
            try:
                payment = PaymentTransaction.objects.select_for_update().get(stripe_session_id=session_id)
            except PaymentTransaction.DoesNotExist:
                return Response({"error": "Payment transaction not found"}, status=404)
            
            sub = payment.subscription

            # FIXED ownership check
            if str(user_id) != str(sub.user_id):
                return Response({"error": "Unauthorized! Session user mismatch"}, status=403)

            # Idempotency
            if payment.status == "success":
                return Response({"message": "Subscription already activated for this session"})

            payment.stripe_payment_intent_id = session.payment_intent
            intent = stripe.PaymentIntent.retrieve(session.payment_intent)

            payment.payment_method = intent.payment_method_types[0] if intent.payment_method_types else "unknown"
            # payment.stripe_charge_id = intent.charges.data[0].id if intent.charges.data else None
            payment.status = "success"
            payment.paid_at = now()
            payment.save()
            
            # Activate subscription
            sub.plan = plan
            sub.status = "active"
            sub.start_date = now().date()

            if plan.interval == "monthly":
                sub.end_date = sub.start_date + timedelta(days=30)
            else:
                sub.end_date = sub.start_date + timedelta(days=365)

            sub.last_payment = payment
            sub.save()

            Invoice.objects.create(
                subscription=sub,
                payment=payment,
                base_amount=payment.base_amount,
                discount_amount=payment.discount_amount,
                gst_amount=payment.gst_amount,
                total_amount=payment.final_amount,
                currency=payment.currency,
                plan_name=plan.name,
                plan_interval=plan.interval,
                stripe_payment_intent_id=payment.stripe_payment_intent_id,
                status='paid',
                invoice_number = f"INV-{payment.id}-{int(now().timestamp())}"
            )

        return Response({"message": "Subscription activated successfully"})

# Remove This
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

        # Create Stripe Checkout Session
        session = create_checkout_session(user, plan)

        # Get or create subscription for user
        sub, _ = Subscription.objects.get_or_create(user=user)

        sub.plan = plan
        sub.status = "none"
        sub.status_session_id = session.id
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

# ========================= # INVOICE VIEWS # ==========================
logger = logging.getLogger(__name__)
pdfmetrics.registerFont(TTFont('DejaVuSans', 'static/fonts/DejaVuSans.ttf'))
class InvoiceGenerator:
    def __init__(self, invoice_id):
        self.invoice_id = invoice_id
        self.invoice = None

    def fetch_invoice(self):
        """
        Fetch the invoice from the database and handle any missing invoice errors.
        """
        try:
            self.invoice = Invoice.objects.get(id=self.invoice_id)
        except ObjectDoesNotExist:
            logger.error(f"Invoice with ID {self.invoice_id} does not exist.")
            raise ValueError("Invoice not found.")
        except Exception as e:
            logger.error(f"Error fetching invoice: {str(e)}", exc_info=True)
            raise Exception("Error fetching invoice data.")

    def generate_pdf(self):
        """
        Generate the PDF for the invoice.
        """
        if not self.invoice:
            raise ValueError("Invoice data is missing. Please fetch the invoice first.")

        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="invoice_{self.invoice.invoice_number}.pdf"'

        # Set up the document layout
        doc = SimpleDocTemplate(
            response, 
            pagesize=letter, 
            rightMargin=inch, 
            leftMargin=inch, 
            topMargin=inch, 
            bottomMargin=inch
        )
        elements = []
        styles = getSampleStyleSheet()
        normal_style = styles['Normal']
        normal_style.fontName = "DejaVuSans"

        # 1. Header (Company Info & INVOICE title)
        header_data = [
            [
                Paragraph("<b>RCube Smart POS</b><br/>123 Tech Lane<br/>Silicon Valley, CA 94025<br/>support@rcubepad.com", normal_style), 
                Paragraph(f"<font size=20><b>INVOICE</b></font><br/><b>Date:</b> {self.invoice.date}<br/><b>Invoice #:</b> {self.invoice.invoice_number}<br/><b>Status:</b> {self.invoice.get_status_display()}", normal_style)
            ]
        ]
        header_table = Table(header_data, colWidths=[3.5*inch, 3*inch])
        header_table.setStyle(TableStyle([
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 40))

        # 2. Bill To Information
        user = self.invoice.subscription.user
        restaurant = self.invoice.subscription.restaurant
        bill_to_text = f"<b>Bill To:</b><br/>{user.first_name or ''} {user.last_name or ''}<br/>{user.email}<br/>"
        
        if restaurant:
            bill_to_text += f"<b>Restaurant:</b> {restaurant.name}<br/>{restaurant.address}<br/>"
        else:
            bill_to_text += f"{user.address or ''}<br/>{user.city or ''} {user.state or ''} {user.pincode or ''}<br/>"
            
        elements.append(Paragraph(bill_to_text, normal_style))
        elements.append(Spacer(1, 30))

        # 3. Line Items Table
        billing_country = getattr(user, 'billing_country', None)
        currency_mapping = {
            'IN': '₹',
            'US': '$',
            'CA': '$',
        }
        currency_symbol = currency_mapping.get(billing_country, '$') if billing_country else '$'
        data = [
            ["Description", "Interval", "Amount"]
        ]
        
        # Add the main subscription item
        data.append([
            f"{self.invoice.plan_name} Subscription",
            self.invoice.plan_interval.capitalize(),
            Paragraph(f"{currency_symbol} {self.invoice.base_amount}", normal_style)
        ])
        
        # Add Billing Details as extra line items (if any)
        billing_details = self.invoice.billing_details or {}
        for key, value in billing_details.items():
            data.append([
                key.capitalize(),
                "—",
                f"{currency_symbol} {value}"
            ])
            
        table = Table(data, colWidths=[4*inch, 1.25*inch, 1.25*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#374151')),
            ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

        # 4. Summary Table (Subtotal, Discount, GST, Total)
        summary_data = [
            ["Subtotal:", Paragraph(f"{currency_symbol} {self.invoice.base_amount}", normal_style)],
            ["Discount:", Paragraph(f"- {currency_symbol} {self.invoice.discount_amount}", normal_style)],
            ["GST / Taxes:", Paragraph(f"{currency_symbol} {self.invoice.gst_amount}", normal_style)],
            ["Total Amount:", Paragraph(f"{currency_symbol} {self.invoice.total_amount}", normal_style)]
        ]
        summary_table = Table(summary_data, colWidths=[5.25*inch, 1.25*inch])
        summary_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LINEABOVE', (0, -1), (-1, -1), 1, colors.black),
            ('LINEBELOW', (0, -1), (-1, -1), 2, colors.black),
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 40))

        # 5. Footer
        footer_text = "<para align=center>Thank you for your business!<br/>If you have any questions regarding this invoice, please contact support.</para>"
        elements.append(Paragraph(footer_text, normal_style))

        # Build the final document
        doc.build(elements)
        return response

    def create_invoice_pdf(self):
        """
        Fetch invoice and generate PDF.
        """
        try:
            self.fetch_invoice()
            return self.generate_pdf()
        except Exception as e:
            logger.error(f"Error creating invoice PDF: {str(e)}", exc_info=True)
            raise Exception(f"Failed to generate invoice PDF: {str(e)}")

class InvoiceGenerationView(APIView):
    """
    View to generate an invoice as a PDF.
    """
    def get(self, request, invoice_id):
        try:
            # Initialize the invoice generator with the provided invoice_id
            user = request.user
            invoice_generator = InvoiceGenerator(invoice_id)
            
            # Check if user is an admin or the owner of the invoice's subscription
            invoice = invoice_generator.fetch_invoice()

            # Generate the invoice PDF
            return invoice_generator.create_invoice_pdf()

        except ValueError as e:
            # Handle case where invoice is not found
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            # Handle any other unexpected errors
            return Response({"error": "An error occurred while generating the invoice", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# ========================= # PLATFORM VIEWS # =========================
class PlatformSettingsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        settings = PlatformSettings.objects.first()
        serializer = PlatformSettingsSerializer(settings)
        return Response(serializer.data)
    



    