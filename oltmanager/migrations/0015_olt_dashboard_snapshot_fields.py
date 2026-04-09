from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0014_configuredonu_status_first_seen_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="dashboard_snapshot_refreshed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="dashboard_temperature",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="olt",
            name="dashboard_uptime",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
    ]
