from datetime import timedelta

from django.utils import timezone


def expiring_olt_subscriptions(request):
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return {}

    try:
        from .models import OLT

        now = timezone.now()
        expires_before = now + timedelta(hours=48)
        olts = list(
            OLT.objects.filter(
                pricing_expires_at__gt=now,
                pricing_expires_at__lte=expires_before,
                pricing_locked=False,
            )
            .only("id", "name", "pricing_expires_at", "pricing_mode")
            .order_by("pricing_expires_at", "name")[:10]
        )
    except Exception:
        olts = []

    return {"expiring_olt_subscriptions": olts}
