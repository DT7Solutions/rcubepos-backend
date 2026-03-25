from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt
from rest_framework.routers import DefaultRouter

from .views import *

router = DefaultRouter()
router.register('restaurants', RestaurantViewSet, basename='restaurants')
router.register('plans', SubscriptionPlanViewSet, basename='plans')
router.register('admin/users', AdminUserViewSet, basename='admin-users')

urlpatterns = [
    # AUTH ENDPOINTS
    # Note: Public auth endpoints use JWT tokens for stateless authentication.
    # CSRF protection is applied via middleware for session-based requests.
    # API clients should:
    # 1. Include Authorization header with JWT token for authenticated requests
    # 2. For initial registration/login, CSRF token is not required (token is returned)
    # 3. Refresh token is set as secure HTTPOnly cookie (auto-sent by browser)

    path('auth/login/', LoginView.as_view()),
    path('auth/register/', RegisterView.as_view()),
    path('auth/verify-otp/', VerifyOTPView.as_view()),
    path('auth/resend-otp/', ResendOTPView.as_view()),
    path('auth/me/', ProfileView.as_view()),
    path('auth/refresh/', RefreshTokenView.as_view()),
    path('auth/change-password/', ChangePasswordView.as_view()),
    path('auth/forgot-password/', ForgotPasswordView.as_view()),
    path('auth/check-availability/', CheckAvailabilityView.as_view()),

    # OWNER FLOW
    path('subscriptions/select-plan/', SelectPlanView.as_view()),
    path('subscriptions/me/', MySubscriptionView.as_view()),

    # API
    path('', include(router.urls)),

    # SETTINGS
    path('settings/', PlatformSettingsView.as_view()),
]