from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0011_olt_pon_ports_cache"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="uplink_cache",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="olt",
            name="uplink_refreshed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="uplink_status",
            field=models.CharField(blank=True, default="", max_length=300),
        ),
    ]
