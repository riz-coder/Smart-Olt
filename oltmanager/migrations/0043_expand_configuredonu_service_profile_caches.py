from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0042_configuredonu_onu_type_cache"),
    ]

    operations = [
        migrations.AlterField(
            model_name="configuredonu",
            name="service_port_id_cache",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AlterField(
            model_name="configuredonu",
            name="user_vlan_cache",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AlterField(
            model_name="configuredonu",
            name="download_profile_index_cache",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AlterField(
            model_name="configuredonu",
            name="upload_profile_index_cache",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AlterField(
            model_name="configuredonu",
            name="download_profile_name_cache",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AlterField(
            model_name="configuredonu",
            name="upload_profile_name_cache",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
