import ipaddress
import secrets
import string

from django import forms

from .models import Plan, Tenant, TenantContact, TenantSnapshot
from . import deployment


def _validate_deployment_form(form, cleaned):
    label = cleaned.get('subdomain', '')
    if label:
        try:
            label = deployment.subdomain_label(label)
            if Tenant.objects.exclude(pk=form.instance.pk).filter(subdomain=label).exists():
                raise ValueError('This subdomain is already in use.')
            cleaned['subdomain'] = label
        except ValueError as exc:
            form.add_error('subdomain', str(exc))
    try:
        deployment.base_domain()
    except ValueError as exc:
        form.add_error(None, str(exc))
    if cleaned.get('vpn_enabled'):
        if not deployment.os.environ.get('CONTROL_VPN_PUBLIC_HOST', '').strip():
            form.add_error(None, 'VPN setup is incomplete. Configure the server public IPv4 address in the deployment settings.')
        try:
            routes = deployment.route_networks(cleaned.get('vpn_routes'))
            if not routes:
                raise ValueError('At least one local or OLT subnet is required.')
            cleaned['vpn_routes'] = '\n'.join(map(str, routes))
        except ValueError as exc:
            form.add_error('vpn_routes', str(exc))
    return cleaned


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
            "subdomain", "vpn_enabled", "client_vpn_port", "vpn_routes",
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

    def clean(self):
        return _validate_deployment_form(self, super().clean())


class TenantCreateForm(forms.ModelForm):
    class Meta:
        model = Tenant
        fields = [
            "name",
            "owner_email",
            "panel_admin_username",
            "panel_admin_initial_password",
            "vpn_enabled",
            "vpn_routes",
        ]
        labels = {
            "name": "ISP / Tenant name",
            "owner_email": "Email",
            "panel_admin_username": "Panel username",
            "panel_admin_initial_password": "Panel initial password",
            "vpn_enabled": "Enable remote-access VPN gateway",
            "vpn_routes": "Remote local/OLT subnet(s)",
        }
        help_texts = {
            "panel_admin_initial_password": "This will be created as the first tenant panel superuser password.",
            "vpn_enabled": "The remote gateway initiates an outbound tunnel, so no client public IP is required.",
            "vpn_routes": "Enter one IPv4 subnet per line. Linux routes only these remote networks through this tenant tunnel.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["owner_email"].required = True
        self.fields["panel_admin_username"].required = True
        self.fields["panel_admin_initial_password"].required = True
        self.fields["vpn_routes"].widget = forms.Textarea(attrs={"rows": 4})
        self.fields["panel_admin_initial_password"].widget = forms.PasswordInput(render_value=True)
        _style_form(self)

    def clean(self):
        return _validate_deployment_form(self, super().clean())

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
            raise forms.ValidationError("Enter a valid subnet, e.g. 10.101.11.0/24.")
        return value

    def clean_client_local_subnet(self):
        return self._clean_subnet("client_local_subnet")

    def clean_olt_management_subnet(self):
        return self._clean_subnet("olt_management_subnet")

    def clean_wg_server_endpoint(self):
        value = str(self.cleaned_data.get("wg_server_endpoint") or "").strip()
        if value and ":" not in value:
            raise forms.ValidationError("The endpoint must include a port, e.g. your-vps-ip:51820.")
        return value

    def save(self, commit=True):
        tenant = super().save(commit=False)
        tenant.isp_name = tenant.name
        tenant.owner_name = tenant.name
        tenant.subdomain = ""
        tenant.client_vpn_port = 51820
        tenant.status = Tenant.STATUS_PROVISIONING
        if not tenant.panel_scheme:
            tenant.panel_scheme = "http"
        if commit:
            tenant.save()
        return tenant


class TenantConnectionForm(forms.ModelForm):
    class Meta:
        model = Tenant
        fields = ['vpn_enabled', 'vpn_routes']
        widgets = {'vpn_routes': forms.Textarea(attrs={'rows': 4})}
        labels = {'vpn_enabled': 'Enable remote-access VPN gateway',
                  'vpn_routes': 'Remote local/OLT subnet(s)'}
        help_texts = {
            'vpn_enabled': 'The remote gateway initiates the tunnel; a public/static client IP is not required.',
            'vpn_routes': 'Enter one IPv4 subnet per line. Linux installs these routes through the tenant tunnel.',
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _style_form(self)

    def clean(self):
        return _validate_deployment_form(self, super().clean())


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
