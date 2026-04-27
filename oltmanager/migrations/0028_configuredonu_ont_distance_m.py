from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0027_configuredonu_capability_cache"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="ont_distance_m",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
    ]
