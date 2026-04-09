from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0010_configuredonu_signal_bucket"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="pon_ports_cache",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="olt",
            name="pon_ports_refreshed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="pon_ports_status",
            field=models.CharField(blank=True, default="", max_length=300),
        ),
    ]
