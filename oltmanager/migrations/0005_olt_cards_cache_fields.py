from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0004_olt_snmp_sync_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="olt_cards_cache",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="olt",
            name="olt_cards_refreshed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="olt_cards_status",
            field=models.CharField(blank=True, default="", max_length=300),
        ),
    ]
