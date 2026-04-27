from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0026_uplinkporttrafficsample"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="capability_synced_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="catv_uni_ports_cache",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="eth_ports_cache",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="onu_type_cache",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="pots_ports_cache",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="uplink_pon_ports_cache",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
    ]
