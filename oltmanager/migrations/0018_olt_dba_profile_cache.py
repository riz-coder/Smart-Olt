from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0017_oltloginhistory_onu_ip_address"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="dba_profile_cache",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="olt",
            name="dba_profile_refreshed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="dba_profile_status",
            field=models.CharField(blank=True, default="", max_length=300),
        ),
    ]
