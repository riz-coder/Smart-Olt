from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0009_onuopticalsample"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="signal_bucket",
            field=models.CharField(blank=True, db_index=True, default="", max_length=16),
        ),
    ]
