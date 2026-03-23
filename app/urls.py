from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import *

router = DefaultRouter()
router.register('restaurants', RestaurantViewSet, basename='restaurants')
router.register('plans', SubscriptionPlanViewSet, basename='plans')
router.register('admin/users', AdminUserViewSet, basename='admin-users')

urlpatterns = [
    # AUTH
    path('auth/login/', LoginView.as_view()),
    path('auth/register/', RegisterView.as_view()),
    path('auth/me/', ProfileView.as_view()),
    path('auth/refresh/', RefreshTokenView.as_view()),
    path('auth/change-password/', ChangePasswordView.as_view()),
    path('auth/forgot-password/', ForgotPasswordView.as_view()),

    # OWNER FLOW
    path('subscriptions/select-plan/', SelectPlanView.as_view()),
    path('subscriptions/me/', MySubscriptionView.as_view()),

    # API
    path('', include(router.urls)),

    # SETTINGS
    path('settings/', PlatformSettingsView.as_view()),
]