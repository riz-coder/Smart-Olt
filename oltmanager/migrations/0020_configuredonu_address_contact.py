from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0019_dashboardstatussample"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="address",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="contact",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
    ]
