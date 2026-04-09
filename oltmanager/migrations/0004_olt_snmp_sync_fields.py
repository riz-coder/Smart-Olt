from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0003_olt_snmp_and_versions"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="snmp_last_status",
            field=models.CharField(blank=True, default="", max_length=300),
        ),
        migrations.AddField(
            model_name="olt",
            name="snmp_last_synced_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
