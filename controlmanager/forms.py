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
            "env_path", "service_name", "notes",
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
