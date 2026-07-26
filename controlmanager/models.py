from decimal import Decimal

from django.conf import settings
from django.db import models
from django.utils.text import slugify


class Plan(models.Model):
    BILLING_FIXED = "fixed"
    BILLING_PER_OLT = "per_olt"
    BILLING_PER_ONU = "per_onu"
    BILLING_CHOICES = [
        (BILLING_FIXED, "Fixed monthly"),
        (BILLING_PER_OLT, "Per OLT"),
        (BILLING_PER_ONU, "Per ONU"),
    ]

    name = models.CharField(max_length=100, unique=True)
    billing_mode = models.CharField(max_length=20, choices=BILLING_CHOICES, default=BILLING_FIXED)
    monthly_price = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal("0.00"))
    max_olts = models.PositiveIntegerField(default=0, help_text="0 means unlimited")
    max_onus = models.PositiveIntegerField(default=0, help_text="0 means unlimited")
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["monthly_price", "name"]

    def __str__(self):
        return self.name


class Tenant(models.Model):
    STATUS_ACTIVE = "active"
    STATUS_SUSPENDED = "suspended"
    STATUS_PROVISIONING = "provisioning"
    STATUS_DISABLED = "disabled"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_SUSPENDED, "Suspended"),
        (STATUS_PROVISIONING, "Provisioning"),
        (STATUS_DISABLED, "Disabled"),
    ]

    name = models.CharField(max_length=140, unique=True)
    slug = models.SlugField(max_length=80, unique=True, blank=True)
    isp_name = models.CharField(max_length=160, blank=True, default="")
    owner_name = models.CharField(max_length=120, blank=True, default="")
    owner_email = models.EmailField(blank=True, default="")
    owner_phone = models.CharField(max_length=60, blank=True, default="")
    plan = models.ForeignKey(Plan, on_delete=models.SET_NULL, null=True, blank=True, related_name="tenants")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PROVISIONING, db_index=True)
    monthly_price_override = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    panel_scheme = models.CharField(max_length=10, default="http")
    panel_host = models.CharField(max_length=160, blank=True, default="")
    panel_port = models.PositiveIntegerField(default=8000)
    panel_base_path = models.CharField(max_length=120, blank=True, default="")
    codebase_path = models.CharField(max_length=255, blank=True, default="")
    database_path = models.CharField(max_length=255, blank=True, default="")
    env_path = models.CharField(max_length=255, blank=True, default="")
    service_name = models.CharField(max_length=120, blank=True, default="")
    panel_admin_username = models.CharField(max_length=120, blank=True, default="")
    panel_admin_initial_password = models.CharField(max_length=160, blank=True, default="")

    last_known_olt_count = models.PositiveIntegerField(default=0)
    last_known_onu_count = models.PositiveIntegerField(default=0)
    last_known_db_size_mb = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    last_reported_at = models.DateTimeField(blank=True, null=True)
    notes = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def save(self, *args, **kwargs):
        if not self.slug:
            base = slugify(self.name)[:70] or "tenant"
            slug = base
            suffix = 2
            while Tenant.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base}-{suffix}"[:80]
                suffix += 1
            self.slug = slug
        super().save(*args, **kwargs)

    @property
    def panel_url(self):
        host = (self.panel_host or "").strip()
        if not host:
            return ""
        scheme = (self.panel_scheme or "http").strip() or "http"
        port = int(self.panel_port or 0)
        path = (self.panel_base_path or "").strip()
        if path and not path.startswith("/"):
            path = f"/{path}"
        default_port = 443 if scheme == "https" else 80
        port_part = "" if port in {0, default_port} else f":{port}"
        return f"{scheme}://{host}{port_part}{path}"

    @property
    def effective_monthly_price(self):
        if self.monthly_price_override is not None:
            return self.monthly_price_override
        return self.plan.monthly_price if self.plan else Decimal("0.00")

    def __str__(self):
        return self.name


class TenantContact(models.Model):
    ROLE_OWNER = "owner"
    ROLE_ADMIN = "admin"
    ROLE_BILLING = "billing"
    ROLE_TECH = "tech"
    ROLE_CHOICES = [
        (ROLE_OWNER, "Owner"),
        (ROLE_ADMIN, "Panel Admin"),
        (ROLE_BILLING, "Billing"),
        (ROLE_TECH, "Technical"),
    ]

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="contacts")
    name = models.CharField(max_length=120)
    email = models.EmailField(blank=True, default="")
    phone = models.CharField(max_length=60, blank=True, default="")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_ADMIN)
    notes = models.CharField(max_length=255, blank=True, default="")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["tenant__name", "role", "name"]

    def __str__(self):
        return f"{self.tenant.name} - {self.name}"


class TenantSnapshot(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="snapshots")
    olt_count = models.PositiveIntegerField(default=0)
    onu_count = models.PositiveIntegerField(default=0)
    db_size_mb = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    app_version = models.CharField(max_length=80, blank=True, default="")
    status_note = models.CharField(max_length=255, blank=True, default="")
    captured_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-captured_at"]

    def __str__(self):
        return f"{self.tenant.name} @ {self.captured_at:%Y-%m-%d %H:%M}"


class TenantOLTSnapshot(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="olt_snapshots")
    tenant_olt_id = models.PositiveIntegerField(default=0, db_index=True)
    name = models.CharField(max_length=160)
    ip_address = models.CharField(max_length=64, blank=True, default="")
    hardware_version = models.CharField(max_length=100, blank=True, default="")
    sw_version = models.CharField(max_length=100, blank=True, default="")
    snmp_last_status = models.CharField(max_length=300, blank=True, default="")
    onu_count = models.PositiveIntegerField(default=0)
    online_count = models.PositiveIntegerField(default=0)
    offline_count = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["tenant__name", "name"]
        unique_together = [("tenant", "tenant_olt_id")]

    def __str__(self):
        return f"{self.tenant.name} - {self.name}"


class ControlAuditLog(models.Model):
    action = models.CharField(max_length=80, db_index=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.SET_NULL, null=True, blank=True)
    details = models.CharField(max_length=300, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["action", "created_at"], name="cp_audit_action_time_idx")]

    def __str__(self):
        return f"{self.action} - {self.created_at:%Y-%m-%d %H:%M}"
