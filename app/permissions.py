from rest_framework.permissions import BasePermission
from django.utils.timezone import now, timedelta
from .models import Subscription

class IsSubscriptionActive(BasePermission):
    """
    Allows access only to users with an active subscription.
    """

    def has_permission(self, request, view):
        user = request.user

        if user.is_staff:
            return True

        if not user.is_authenticated:
            return False

        subscription = Subscription.objects.filter(user=user).select_related('plan').first()
        
        if not subscription or not subscription.plan:
            return False
        
        return subscription.status in ['active', 'trialing'] and subscription.current_period_end > now()
    
