from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0028_configuredonu_ont_distance_m"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="attached_vlans_cache",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="attached_vlans_synced_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
