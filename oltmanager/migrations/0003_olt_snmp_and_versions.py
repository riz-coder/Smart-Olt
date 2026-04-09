from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0002_alter_olt_port"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="hardware_version",
            field=models.CharField(blank=True, default="", max_length=100),
        ),
        migrations.AddField(
            model_name="olt",
            name="snmp_community",
            field=models.CharField(default="public", max_length=100),
        ),
        migrations.AddField(
            model_name="olt",
            name="snmp_port",
            field=models.IntegerField(default=161, help_text="SNMP UDP port"),
        ),
        migrations.AddField(
            model_name="olt",
            name="sw_version",
            field=models.CharField(blank=True, default="", max_length=100),
        ),
    ]
