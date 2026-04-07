from django.contrib import admin
from .models import *

# ================= USERS =================
@admin.register(Users)
class UsersAdmin(admin.ModelAdmin):
    list_display = ('id', 'username', 'email', 'phone', 'role', 'is_staff', 'is_active')
    search_fields = ('username', 'email', 'phone')
    list_filter = ('role', 'is_staff', 'is_active')
    ordering = ('-created_at',)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('id', 'role_name', 'role_category', 'created_at')
    search_fields = ('role_name',)


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'created_by', 'created_at')


# ================= RESTAURANT =================
@admin.register(Restaurant)
class RestaurantAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'owner', 'status', 'created_at')
    search_fields = ('name', 'owner__username')
    list_filter = ('status',)
    ordering = ('-created_at',)


# ================= SUBSCRIPTION =================
@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'price', 'interval', 'is_active', 'popular')
    list_filter = ('interval', 'is_active')


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'restaurant', 'plan', 'status', 'start_date', 'end_date')
    list_filter = ('status',)
    search_fields = ('user__username', 'restaurant__name')
    ordering = ('-created_at',)


# ================= PAYMENT =================
class RefundInline(admin.TabularInline):
    model = Refund
    extra = 0
    readonly_fields = ('amount', 'stripe_refund_id', 'created_at')

class InvoiceInline(admin.TabularInline):
    model = Invoice
    extra = 0
    readonly_fields = ('invoice_number', 'total_amount', 'status')

@admin.register(PaymentTransaction)
class PaymentTransactionAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'user', 'subscription', 'status',
        'base_amount', 'discount_amount', 'gst_amount', 'final_amount',
        'refunded_amount', 'payment_method', 'created_at'
    )

    list_filter = ('status', 'payment_method', 'currency')
    search_fields = (
        'user__username',
        'stripe_payment_intent_id',
        'stripe_session_id'
    )

    readonly_fields = (
        'stripe_session_id',
        'stripe_payment_intent_id',
        'stripe_charge_id',
        'created_at',
        'paid_at'
    )

    ordering = ('-created_at',)

    inlines = [RefundInline, InvoiceInline]


# ================= REFUNDS =================

@admin.register(Refund)
class RefundAdmin(admin.ModelAdmin):
    list_display = ('id', 'payment', 'amount', 'stripe_refund_id', 'created_at')
    search_fields = ('stripe_refund_id', 'payment__stripe_payment_intent_id')
    ordering = ('-created_at',)


# ================= INVOICE =================
@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'subscription', 'base_amount', 'discount_amount',
        'gst_amount', 'total_amount', 'status', 'date'
    )

    list_filter = ('status', 'plan_interval')
    search_fields = ('invoice_number', 'subscription__user__username')

    readonly_fields = ('invoice_number', 'created_at')

    ordering = ('-created_at',)


# ================= PLATFORM =================
@admin.register(PlatformSettings)
class PlatformSettingsAdmin(admin.ModelAdmin):
    list_display = ('gst_percent', 'currency')


# ================= STRIPE LOGS =================
@admin.register(StripeWebhookLog)
class StripeWebhookLogAdmin(admin.ModelAdmin):
    list_display = ('event_id', 'event_type', 'processed', 'created_at')
    search_fields = ('event_id', 'event_type')
    list_filter = ('processed',)
    ordering = ('-created_at',)