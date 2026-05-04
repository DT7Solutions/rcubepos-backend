import stripe
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'rcubepos.settings')
django.setup()

from django.conf import settings
stripe.api_key = settings.STRIPE_SECRET_KEY

invoice_id = "in_1TRSBkPQvds7NOzRD2493Xdd"

print(f"=== Fetching Invoice {invoice_id} with NEW v15 API ===\n")

# Expand only 4 levels max
inv = stripe.Invoice.retrieve(
    invoice_id,
    expand=["payments.data.payment.payment_intent"],
)

print(f"inv.id: {inv.id}")

payments = getattr(inv, "payments", None)
print(f"inv.payments type: {type(payments)}")

if payments and hasattr(payments, "data"):
    print(f"payments.data length: {len(payments.data)}")
    for i, ip in enumerate(payments.data):
        print(f"\n--- Payment [{i}] ---")
        
        payment_obj = getattr(ip, "payment", None)
        if payment_obj:
            pi = getattr(payment_obj, "payment_intent", None)
            print(f"  payment.payment_intent type: {type(pi)}")
            
            if pi and hasattr(pi, "id"):
                print(f"  *** PI id: {pi.id} ***")
                
                # payment_method on PI (may be string ID since we hit expand limit)
                pm_raw = getattr(pi, "payment_method", None)
                print(f"  pi.payment_method type: {type(pm_raw)}, value: {pm_raw}")
                
                if isinstance(pm_raw, str):
                    # Fetch the PM separately
                    pm_obj = stripe.PaymentMethod.retrieve(pm_raw)
                    print(f"  *** PM type (fetched): {pm_obj.type} ***")
                    billing = getattr(pm_obj, "billing_details", None)
                    if billing:
                        address = getattr(billing, "address", None)
                        print(f"  *** Country: {getattr(address, 'country', None)} ***")
                elif pm_raw and hasattr(pm_raw, "type"):
                    print(f"  *** PM type (expanded): {pm_raw.type} ***")
            elif isinstance(pi, str):
                print(f"  PI is string ID: {pi}")
        else:
            print(f"  payment_obj is None")
else:
    print("No payments data found")
