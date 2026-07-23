from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0041_remove_configuredonu_unused_capability_cache"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="onu_type_cache",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
    ]
