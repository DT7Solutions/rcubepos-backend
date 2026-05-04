import stripe
import os
import django
import logging

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'rcubepos.settings')
django.setup()

from app.utils import extract_stripe_payment_details

logger = logging.getLogger("test")
logging.basicConfig(level=logging.INFO)

invoice_id = "in_1TRSBkPQvds7NOzRD2493Xdd"
print(f"Testing extraction for {invoice_id}...")

details = extract_stripe_payment_details(invoice_id, logger)
print("\n--- RESULTS ---")
for k, v in details.items():
    print(f"{k}: {v}")
