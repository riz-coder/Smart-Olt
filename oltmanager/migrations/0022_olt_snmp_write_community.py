from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0021_olt_autofind_count_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="snmp_write_community",
            field=models.CharField(blank=True, default="", max_length=100),
        ),
    ]
