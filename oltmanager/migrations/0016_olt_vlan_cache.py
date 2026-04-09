from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0015_olt_dashboard_snapshot_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="vlan_cache",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="olt",
            name="vlan_refreshed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="vlan_status",
            field=models.CharField(blank=True, default="", max_length=300),
        ),
    ]
