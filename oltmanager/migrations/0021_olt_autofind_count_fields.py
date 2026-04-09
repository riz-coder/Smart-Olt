from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0020_configuredonu_address_contact"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="autofind_onu_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="olt",
            name="autofind_refreshed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="autofind_status",
            field=models.CharField(blank=True, default="", max_length=300),
        ),
    ]
