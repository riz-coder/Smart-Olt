from django.contrib import admin
from .models import ClientPanel, ControlAuditLog, OLT, SubscriptionPlan, UserProfile


@admin.register(OLT)
class OLTAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "ip_address",
        "port",
        "snmp_port",
        "hardware_version",
        "sw_version",
        "username",
        "vendor",
        "client_panel",
        "service_enabled",
        "created_at",
    )
    search_fields = ("name", "ip_address", "vendor", "username", "hardware_version", "sw_version")
    list_filter = ("vendor", "service_enabled", "client_panel", "port", "snmp_port", "created_at")
    ordering = ("-created_at",)


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ("name", "billing_mode", "monthly_price", "max_olts", "max_onus", "is_active")
    list_filter = ("billing_mode", "is_active")
    search_fields = ("name",)


@admin.register(ClientPanel)
class ClientPanelAdmin(admin.ModelAdmin):
    list_display = ("name", "status", "plan", "contact_name", "contact_email", "updated_at")
    list_filter = ("status", "plan")
    search_fields = ("name", "contact_name", "contact_email", "contact_phone")


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "client_panel", "role", "updated_at")
    list_filter = ("role", "client_panel")
    search_fields = ("user__username", "user__first_name", "client_panel__name")


@admin.register(ControlAuditLog)
class ControlAuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "user", "client_panel", "olt", "created_at")
    list_filter = ("action", "created_at")
    search_fields = ("details", "user__username", "client_panel__name", "olt__name")
    readonly_fields = ("action", "user", "client_panel", "olt", "details", "created_at")


admin.site.site_header = "OLT Control Center"
admin.site.site_title = "OLT Admin"
admin.site.index_title = "Network Device Management"
