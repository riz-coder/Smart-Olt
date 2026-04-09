from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0016_olt_vlan_cache"),
    ]

    operations = [
        migrations.AddField(
            model_name="oltloginhistory",
            name="ip_address",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="oltloginhistory",
            name="onu",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
    ]
