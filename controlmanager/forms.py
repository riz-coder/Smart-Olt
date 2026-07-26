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
        fields = ["name", "owner_email", "panel_admin_username", "panel_admin_initial_password"]
        labels = {
            "name": "ISP / Tenant name",
            "owner_email": "Email",
            "panel_admin_username": "Panel username",
            "panel_admin_initial_password": "Panel initial password",
        }
        help_texts = {
            "panel_admin_initial_password": "This will be created as the first tenant panel superuser password.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["owner_email"].required = True
        self.fields["panel_admin_username"].required = True
        self.fields["panel_admin_initial_password"].required = True
        _style_form(self)

    def clean_panel_admin_initial_password(self):
        value = str(self.cleaned_data.get("panel_admin_initial_password") or "").strip()
        if value:
            return value
        alphabet = string.ascii_letters + string.digits + "!@#$%*-_"
        return "".join(secrets.choice(alphabet) for _ in range(14))

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
