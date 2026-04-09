from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0013_configuredonu_status_and_onutrapevent"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="status_first_seen_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
