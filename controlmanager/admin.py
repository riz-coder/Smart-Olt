from django.contrib import admin

from .models import ControlAuditLog, Plan, Tenant, TenantContact, TenantOLTSnapshot, TenantSnapshot


class TenantContactInline(admin.TabularInline):
    model = TenantContact
    extra = 0


class TenantSnapshotInline(admin.TabularInline):
    model = TenantSnapshot
    extra = 0
    readonly_fields = ("captured_at",)
    fields = ("olt_count", "onu_count", "db_size_mb", "app_version", "status_note", "captured_at")


class TenantOLTSnapshotInline(admin.TabularInline):
    model = TenantOLTSnapshot
    extra = 0
    readonly_fields = ("updated_at",)
    fields = ("name", "ip_address", "hardware_version", "onu_count", "online_count", "offline_count", "snmp_last_status", "updated_at")


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ("name", "status", "panel_host", "panel_port", "plan", "last_known_olt_count", "last_known_onu_count", "updated_at")
    list_filter = ("status", "plan", "panel_scheme")
    search_fields = ("name", "slug", "isp_name", "owner_name", "owner_email", "panel_host", "database_path")
    prepopulated_fields = {"slug": ("name",)}
    inlines = [TenantContactInline, TenantOLTSnapshotInline, TenantSnapshotInline]


@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    list_display = ("name", "billing_mode", "monthly_price", "max_olts", "max_onus", "is_active")
    list_filter = ("billing_mode", "is_active")
    search_fields = ("name",)


@admin.register(TenantContact)
class TenantContactAdmin(admin.ModelAdmin):
    list_display = ("tenant", "name", "role", "email", "phone", "is_active")
    list_filter = ("role", "is_active")
    search_fields = ("tenant__name", "name", "email", "phone")


@admin.register(TenantSnapshot)
class TenantSnapshotAdmin(admin.ModelAdmin):
    list_display = ("tenant", "olt_count", "onu_count", "db_size_mb", "app_version", "captured_at")
    list_filter = ("captured_at",)
    search_fields = ("tenant__name", "app_version", "status_note")


@admin.register(TenantOLTSnapshot)
class TenantOLTSnapshotAdmin(admin.ModelAdmin):
    list_display = ("tenant", "name", "ip_address", "onu_count", "online_count", "offline_count", "updated_at")
    list_filter = ("tenant", "hardware_version")
    search_fields = ("tenant__name", "name", "ip_address")


@admin.register(ControlAuditLog)
class ControlAuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "tenant", "user", "created_at")
    list_filter = ("action", "created_at")
    search_fields = ("details", "tenant__name", "user__username")
    readonly_fields = ("action", "tenant", "user", "details", "created_at")
