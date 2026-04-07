from rest_framework.permissions import BasePermission
from django.utils.timezone import now, timedelta

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

        subscription = (subscription.objects.filter(user=user).select_related('plan').first())
        
        if not subscription or not subscription.plan:
            return False
        
        return subscription.get_status() == 'active'
    
