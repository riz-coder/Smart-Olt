from django.contrib import admin
from .models import OLT, TenantProvisioning


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
        "created_at",
    )
    search_fields = ("name", "ip_address", "vendor", "username", "hardware_version", "sw_version")
    list_filter = ("vendor", "port", "snmp_port", "created_at")
    ordering = ("-created_at",)


@admin.register(TenantProvisioning)
class TenantProvisioningAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "slug",
        "client_public_ip",
        "client_vpn_port",
        "olt_management_subnet",
        "status",
        "last_heartbeat_at",
        "created_at",
    )
    search_fields = ("name", "slug", "client_public_ip", "client_local_subnet", "olt_management_subnet")
    list_filter = ("status", "created_at")
    readonly_fields = (
        "agent_token",
        "wg_client_private_key",
        "wg_client_public_key",
        "created_at",
        "updated_at",
    )
    ordering = ("name",)


admin.site.site_header = "OLT Control Center"
admin.site.site_title = "OLT Admin"
admin.site.index_title = "Network Device Management"
