import ipaddress
import re
import secrets
import string

from django import forms

from .models import Plan, Tenant, TenantContact, TenantSnapshot


class PlanForm(forms.ModelForm):
    class Meta:
        model = Plan
        fields = ["name", "billing_mode", "monthly_price", "max_olts", "max_onus", "is_active", "notes"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _style_form(self)


class TenantForm(forms.ModelForm):
    class Meta:
        model = Tenant
        fields = [
            "name", "slug", "isp_name", "owner_name", "owner_email", "owner_phone",
            "plan", "status", "monthly_price_override", "panel_scheme", "panel_host",
            "panel_port", "panel_base_path", "codebase_path", "database_path",
            "env_path", "service_name", "panel_admin_username", "panel_admin_initial_password", "notes",
        ]
        help_texts = {
            "slug": "Leave blank to generate automatically.",
            "database_path": "Metadata only. Control plane will not open this tenant DB.",
            "codebase_path": "Example: /opt/optiverse/tenants/acme/Smart-Olt",
            "service_name": "Example: optiverse-acme.service",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["plan"].queryset = Plan.objects.filter(is_active=True).order_by("name")
        _style_form(self)

    def clean_slug(self):
        value = str(self.cleaned_data.get("slug") or "").strip().lower()
        return value


class TenantCreateForm(forms.ModelForm):
    class Meta:
        model = Tenant
        fields = [
            "name",
            "owner_email",
            "panel_admin_username",
            "panel_admin_initial_password",
            "client_public_ip",
            "client_vpn_port",
            "client_local_subnet",
            "olt_management_subnet",
            "wg_server_endpoint",
            "wg_server_public_key",
            "docker_image",
        ]
        labels = {
            "name": "ISP / Tenant name",
            "owner_email": "Email",
            "panel_admin_username": "Panel username",
            "panel_admin_initial_password": "Panel initial password",
            "client_public_ip": "Client public IP",
            "client_vpn_port": "Client VPN port",
            "client_local_subnet": "Client local subnet",
            "olt_management_subnet": "OLT management subnet",
            "wg_server_endpoint": "VPS WireGuard endpoint",
            "wg_server_public_key": "VPS WireGuard public key",
            "docker_image": "Tenant Docker image",
        }
        help_texts = {
            "panel_admin_initial_password": "This will be created as the first tenant panel superuser password.",
            "client_public_ip": "Client/router public IP. Local tenant me blank chhor sakte hain.",
            "client_vpn_port": "Usually 51820.",
            "client_local_subnet": "Client LAN subnet, e.g. 192.168.10.0/24. Local tenant me blank allowed.",
            "olt_management_subnet": "OLT subnet reachable from tenant, e.g. 10.101.11.0/24.",
            "wg_server_endpoint": "VPS endpoint, e.g. your-vps-ip:51820. Local/no-VPN tenant me blank allowed.",
            "wg_server_public_key": "VPS WireGuard public key. Local/no-VPN tenant me blank allowed.",
            "docker_image": "Default: optiverse-tenant-app:latest",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["owner_email"].required = True
        self.fields["panel_admin_username"].required = True
        self.fields["panel_admin_initial_password"].required = True
        self.fields["client_public_ip"].required = False
        self.fields["client_vpn_port"].required = False
        self.fields["client_vpn_port"].initial = 51820
        self.fields["client_local_subnet"].required = False
        self.fields["olt_management_subnet"].required = False
        self.fields["wg_server_endpoint"].required = False
        self.fields["wg_server_public_key"].required = False
        self.fields["docker_image"].required = False
        self.fields["docker_image"].initial = "optiverse-tenant-app:latest"
        _style_form(self)

    def clean_panel_admin_initial_password(self):
        value = str(self.cleaned_data.get("panel_admin_initial_password") or "").strip()
        if value:
            return value
        alphabet = string.ascii_letters + string.digits + "!@#$%*-_"
        return "".join(secrets.choice(alphabet) for _ in range(14))

    def _clean_subnet(self, field_name):
        value = str(self.cleaned_data.get(field_name) or "").strip()
        if not value:
            return value
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise forms.ValidationError("Valid subnet enter karein, e.g. 10.101.11.0/24.")
        return value

    def clean_client_local_subnet(self):
        return self._clean_subnet("client_local_subnet")

    def clean_olt_management_subnet(self):
        return self._clean_subnet("olt_management_subnet")

    def clean_wg_server_endpoint(self):
        value = str(self.cleaned_data.get("wg_server_endpoint") or "").strip()
        if value and ":" not in value:
            raise forms.ValidationError("Endpoint me port bhi hona chahiye, e.g. your-vps-ip:51820.")
        return value

    def clean_docker_image(self):
        value = str(self.cleaned_data.get("docker_image") or "").strip() or "optiverse-tenant-app:latest"
        if not re.match(r"^[a-zA-Z0-9._:/-]+$", value):
            raise forms.ValidationError("Docker image me invalid characters hain.")
        return value

    def save(self, commit=True):
        tenant = super().save(commit=False)
        tenant.isp_name = tenant.name
        tenant.owner_name = tenant.name
        tenant.status = Tenant.STATUS_PROVISIONING
        if not tenant.panel_scheme:
            tenant.panel_scheme = "http"
        if commit:
            tenant.save()
        return tenant


class TenantContactForm(forms.ModelForm):
    class Meta:
        model = TenantContact
        fields = ["name", "email", "phone", "role", "is_active", "notes"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _style_form(self)
        self.fields["is_active"].widget.attrs["class"] = ""


class TenantSnapshotForm(forms.ModelForm):
    class Meta:
        model = TenantSnapshot
        fields = ["olt_count", "onu_count", "db_size_mb", "app_version", "status_note"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _style_form(self)


def _style_form(form):
    for field in form.fields.values():
        css = field.widget.attrs.get("class", "")
        field.widget.attrs["class"] = f"{css} cp-input".strip()
