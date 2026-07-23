from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0039_configuredonu_ethernet_port_config_cache"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="is_ready",
            field=models.BooleanField(db_index=True, default=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="onboarding_finished_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="onboarding_log",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="olt",
            name="onboarding_message",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="olt",
            name="onboarding_progress",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="olt",
            name="onboarding_started_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="onboarding_status",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
    ]
