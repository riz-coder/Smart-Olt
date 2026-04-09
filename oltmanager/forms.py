import re

from django import forms

from .models import OLT

HUAWEI_HARDWARE_CHOICES = [
    ("", "Select Huawei OLT hardware"),
    ("MA5608T", "Huawei MA5608T"),
    ("MA5608", "Huawei MA5608"),
    ("MA5603T", "Huawei MA5603T"),
    ("MA5603", "Huawei MA5603"),
    ("MA5680T", "Huawei MA5680T"),
    ("MA5683T", "Huawei MA5683T"),
    ("MA5683", "Huawei MA5683"),
    ("MA5800-X2", "Huawei MA5800-X2"),
    ("MA5800-X7", "Huawei MA5800-X7"),
    ("MA5800-X15", "Huawei MA5800-X15"),
    ("MA5800-X17", "Huawei MA5800-X17"),
]


class OLTForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            css_class = field.widget.attrs.get('class', '')
            field.widget.attrs['class'] = f"{css_class} form-control".strip()
        if self.instance and self.instance.pk:
            # Show saved credentials on edit; blank submit still keeps old password in clean_password.
            self.fields['username'].initial = self.instance.username
            self.fields['password'].initial = self.instance.password
            self.fields['password'].required = False
            self.fields['password'].help_text = 'Leave blank to keep current password'

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if password:
            return password
        if self.instance and self.instance.pk:
            return self.instance.password
        raise forms.ValidationError('Password is required.')

    class Meta:
        model = OLT
        fields = [
            'name',
            'ip_address',
            'port',
            'snmp_port',
            'snmp_community',
            'username',
            'password',
            'vendor',
            'hardware_version',
        ]
        widgets = {
            'password': forms.PasswordInput(render_value=True),
            'hardware_version': forms.Select(choices=HUAWEI_HARDWARE_CHOICES),
        }
        labels = {
            'port': 'TCP (Telnet)',
            'snmp_port': 'UDP (SNMP)',
            'snmp_community': 'SNMP community string',
            'hardware_version': 'OLT Hardware Version',
        }
        help_texts = {
            'port': 'Default Telnet port is 23',
            'snmp_port': 'Default SNMP UDP port is 161',
            'snmp_community': 'This community will be pushed to the OLT over Telnet.',
            'hardware_version': 'Select your Huawei OLT hardware model',
        }


DBA_PROFILE_TYPE_CHOICES = [(f"type{index}", f"Type {index}") for index in range(1, 6)]


class DBAProfileAddForm(forms.Form):
    profile_id = forms.IntegerField(
        min_value=10,
        max_value=512,
        label="Profile ID",
        help_text="Profile ID must be 10 or higher.",
        error_messages={
            "required": "Profile ID is required.",
            "invalid": "Profile ID must be a number between 10 and 512.",
            "min_value": "Profile ID must be between 10 and 512.",
            "max_value": "Profile ID must be between 10 and 512.",
        },
    )
    profile_name = forms.CharField(
        max_length=20,
        label="Profile Name",
        error_messages={
            "required": "Profile name is required.",
            "max_length": "Profile name must be 20 characters or fewer.",
        },
    )
    profile_type = forms.ChoiceField(
        choices=DBA_PROFILE_TYPE_CHOICES,
        label="Type",
    )
    dba_speed = forms.IntegerField(
        min_value=1,
        label="DBA Speed",
        help_text="Enter the speed in Mbps. The OLT command will use this value x 1024.",
        error_messages={
            "required": "DBA speed is required.",
            "invalid": "DBA speed must be a positive number.",
            "min_value": "DBA speed must be a positive number.",
        },
    )

    def __init__(self, *args, **kwargs):
        reserved_ids = kwargs.pop("reserved_ids", None)
        reserved_names = kwargs.pop("reserved_names", None)
        super().__init__(*args, **kwargs)
        self.reserved_ids = {int(value) for value in (reserved_ids or set())}
        self.reserved_names = {str(value or "").strip().lower() for value in (reserved_names or set()) if str(value or "").strip()}
        for field in self.fields.values():
            css_class = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{css_class} form-control".strip()
        self.fields["profile_name"].widget.attrs["placeholder"] = "88MB"
        self.fields["dba_speed"].widget.attrs["placeholder"] = "88"

    def clean_profile_id(self):
        profile_id = int(self.cleaned_data["profile_id"])
        if profile_id < 10 or profile_id > 512:
            raise forms.ValidationError("Profile ID must be between 10 and 512.")
        if profile_id in self.reserved_ids:
            raise forms.ValidationError("This profile ID is already in use on the OLT.")
        return profile_id

    def clean_profile_name(self):
        profile_name = str(self.cleaned_data["profile_name"] or "").strip()
        if not profile_name:
            raise forms.ValidationError("Profile name is required.")
        if '"' in profile_name:
            raise forms.ValidationError('Double quotes are not allowed in the profile name.')
        if len(profile_name) > 20:
            raise forms.ValidationError("Profile name must be 20 characters or fewer.")
        if profile_name.lower() in self.reserved_names:
            raise forms.ValidationError("This profile name is already in use on the OLT.")
        return profile_name

    def clean_dba_speed(self):
        dba_speed = int(self.cleaned_data["dba_speed"])
        max_value = dba_speed * 1024
        if max_value < 128 or max_value > 10000000:
            raise forms.ValidationError("DBA speed is out of allowed range after conversion.")
        return dba_speed


class VLANAddForm(forms.Form):
    vlan_id = forms.IntegerField(
        min_value=1,
        max_value=4094,
        label="VLAN ID",
        error_messages={
            "required": "VLAN ID is required.",
            "invalid": "VLAN ID must be a number between 1 and 4094.",
            "min_value": "VLAN ID must be between 1 and 4094.",
            "max_value": "VLAN ID must be between 1 and 4094.",
        },
    )
    description = forms.CharField(
        required=False,
        max_length=20,
        label="Description",
        error_messages={
            "max_length": "Description must be 20 characters or fewer.",
        },
    )

    def __init__(self, *args, **kwargs):
        reserved_ids = kwargs.pop("reserved_ids", None)
        super().__init__(*args, **kwargs)
        self.reserved_ids = {int(value) for value in (reserved_ids or set())}
        for field in self.fields.values():
            css_class = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{css_class} form-control".strip()
        self.fields["vlan_id"].widget.attrs["placeholder"] = "39"
        self.fields["description"].widget.attrs["placeholder"] = "SM"

    def clean_vlan_id(self):
        vlan_id = int(self.cleaned_data["vlan_id"])
        if vlan_id < 1 or vlan_id > 4094:
            raise forms.ValidationError("VLAN ID must be between 1 and 4094.")
        if vlan_id in self.reserved_ids:
            raise forms.ValidationError("This VLAN already exists on the OLT.")
        return vlan_id

    def clean_description(self):
        description = str(self.cleaned_data.get("description") or "").strip()
        if len(description) > 20:
            raise forms.ValidationError("Description must be 20 characters or fewer.")
        if '"' in description:
            raise forms.ValidationError('Double quotes are not allowed in the description.')
        return description


class VLANBulkAddForm(forms.Form):
    vlan_range = forms.CharField(
        max_length=32,
        label="VLAN Range",
        error_messages={
            "required": "VLAN range is required.",
            "max_length": "VLAN range is too long.",
        },
    )

    def __init__(self, *args, **kwargs):
        reserved_ids = kwargs.pop("reserved_ids", None)
        super().__init__(*args, **kwargs)
        self.reserved_ids = {int(value) for value in (reserved_ids or set())}
        for field in self.fields.values():
            css_class = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{css_class} form-control".strip()
        self.fields["vlan_range"].widget.attrs["placeholder"] = "150-160"

    def clean_vlan_range(self):
        raw_value = str(self.cleaned_data.get("vlan_range") or "").strip()
        match = re.match(r"^(\d+)\s*-\s*(\d+)$", raw_value)
        if not match:
            raise forms.ValidationError("Enter VLAN range like 150-160.")
        start = int(match.group(1))
        end = int(match.group(2))
        if start < 1 or end > 4094 or start >= end:
            raise forms.ValidationError("VLAN range must stay between 1 and 4094, and end must be greater than start.")
        count = (end - start) + 1
        if count > 11:
            raise forms.ValidationError("You can add up to 11 VLANs at a time.")
        existing = [str(vlan_id) for vlan_id in range(start, end + 1) if vlan_id in self.reserved_ids]
        if existing:
            raise forms.ValidationError(f"These VLANs already exist on the OLT: {', '.join(existing[:6])}")
        return {"raw": f"{start}-{end}", "start": start, "end": end, "count": count}
