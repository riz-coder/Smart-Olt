from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0064_configured_onu_dashboard_indexes"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="configuredonu",
            index=models.Index(
                fields=["olt", "status_updated_at", "id"],
                name="conf_onu_olt_status_time_idx",
            ),
        ),
    ]
