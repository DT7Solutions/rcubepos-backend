from django.utils.timezone import now
from .models import Subscription
import logging

logger = logging.getLogger(__name__)

def expire_lapsed_subscriptions():
    """
    Safety net: mark subscriptions as past_due if Stripe's billing period
    has ended and we never received a renewal webhook.
    Only touches subscriptions with a known current_period_end.
    """
    lapsed = Subscription.objects.filter(
        status='active',
        current_period_end__lt=now(),
        current_period_end__isnull=False,
    )

    count = lapsed.count()
    if count:
        lapsed.update(status='past_due')
        logger.warning(
            f"expire_lapsed_subscriptions: marked {count} subscription(s) "
            f"as past_due due to expired billing period"
        )
