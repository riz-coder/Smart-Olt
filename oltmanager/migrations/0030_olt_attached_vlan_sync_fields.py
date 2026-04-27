from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0029_configuredonu_attached_vlans_cache_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="attached_vlan_sync_cursor_pk",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="olt",
            name="attached_vlan_sync_status",
            field=models.CharField(blank=True, default="", max_length=300),
        ),
        migrations.AddField(
            model_name="olt",
            name="attached_vlan_sync_updated_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
