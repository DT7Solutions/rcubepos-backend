from django.core.management.base import BaseCommand
from django.conf import settings
import stripe

from app.models import *
from app.utils import *

class Command(BaseCommand):
    help = "Sync Stripe products and prices (test/live)"

    def handle(self, *args, **kwargs):
        stripe.api_key = settings.STRIPE_SECRET_KEY

        is_live = settings.STRIPE_LIVE_MODE

        self.stdout.write(self.style.WARNING(
            f"Running Stripe sync in {'LIVE' if is_live else 'TEST'} mode"
        ))

        if is_live and not getattr(settings, "ALLOW_STRIPE_LIVE_MUTATION", False):
            self.stdout.write(self.style.ERROR(
                "Live mutation not allowed. Set ALLOW_STRIPE_LIVE_MUTATION=True"
            ))
            return

        plans = SubscriptionPlan.objects.filter(is_active=True)

        for plan in plans:
            self.stdout.write(f"\nProcessing Plan: {plan.name} ({plan.interval})")

            product_field = "stripe_product_id_live" if is_live else "stripe_product_id_test"

            product_id = getattr(plan, product_field)

            # ── Create Product ─────────────────────────────
            if not product_id:
                product = create_stripe_product(plan)

                setattr(plan, product_field, product.id)
                plan.save(update_fields=[product_field])

                product_id = product.id
                self.stdout.write(self.style.SUCCESS(f"Created product: {product_id}"))
            else:
                self.stdout.write(f"Using existing product: {product_id}")

            # ── Pricing ────────────────────────────────────
            pricings = plan.pricings.filter(is_active=True)

            for pricing in pricings:
                price_field = "stripe_price_id_live" if is_live else "stripe_price_id_test"

                price_id = getattr(pricing, price_field)

                if not price_id:
                    price = create_stripe_price(product_id, pricing)

                    setattr(pricing, price_field, price.id)
                    pricing.save(update_fields=[price_field])

                    self.stdout.write(self.style.SUCCESS(
                        f"Created price: {price.id} ({pricing.currency} {pricing.price})"
                    ))
                else:
                    self.stdout.write(f"Using existing price: {price_id}")

        self.stdout.write(self.style.SUCCESS("\nStripe sync completed successfully"))