from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0007_configuredonu"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="olt_rx",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="onu_rx",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="tx_power",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
    ]
