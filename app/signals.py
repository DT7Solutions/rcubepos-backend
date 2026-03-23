from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Users, Role


@receiver(post_save, sender=Users)
def assign_default_role(sender, instance, created, **kwargs):
    if created:
        owner_role, _ = Role.objects.get_or_create(
            role_name='Owner',
            defaults={'role_category': 'owner'}
        )

        # Assign role only if not already set
        if not instance.role:
            instance.role = owner_role
            instance.save()