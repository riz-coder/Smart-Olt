from django.contrib import admin
from .models import OLT


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


admin.site.site_header = "OLT Control Center"
admin.site.site_title = "OLT Admin"
admin.site.index_title = "Network Device Management"
