from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0046_onustatussample"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="stability_report_date",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="stability_report_cache",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
