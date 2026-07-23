from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0033_merge_20260427_2015"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="online_duration_cache",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="last_up_time_cache",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="last_down_time_cache",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="last_down_cause_cache",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="battery_state_cache",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="onu_mode_cache",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="runtime_synced_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
