import uuid

from django.db import migrations, models


def populate_licence_refs(apps, schema_editor):
    OLT = apps.get_model("oltmanager", "OLT")
    for olt in OLT.objects.filter(licence_ref__isnull=True).iterator():
        olt.licence_ref = uuid.uuid4()
        olt.save(update_fields=["licence_ref"])


class Migration(migrations.Migration):
    dependencies = [
        ("oltmanager", "0065_configured_onu_status_time_index"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="onboarding_snmp_mode",
            field=models.CharField(blank=True, default="manual", max_length=16),
        ),
        migrations.AddField(
            model_name="olt",
            name="licence_ref",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.RunPython(populate_licence_refs, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="olt",
            name="licence_ref",
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="licence_status",
            field=models.CharField(blank=True, db_index=True, default="legacy", max_length=20),
        ),
        migrations.AddField(
            model_name="olt",
            name="licence_invoice_url",
            field=models.URLField(blank=True, default="", max_length=500),
        ),
    ]
