from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0022_olt_snmp_write_community"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="autofind_new_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="olt",
            name="autofind_resync_count",
            field=models.PositiveIntegerField(default=0),
        ),
    ]
