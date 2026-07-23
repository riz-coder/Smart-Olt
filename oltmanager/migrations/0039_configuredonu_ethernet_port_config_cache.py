from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0038_configuredonu_profile_cache_restore"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="ethernet_port_config_cache",
            field=models.TextField(blank=True, default=""),
        ),
    ]
