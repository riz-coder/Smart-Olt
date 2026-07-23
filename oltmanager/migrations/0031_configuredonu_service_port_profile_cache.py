from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oltmanager', '0030_olt_attached_vlan_sync_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='configuredonu',
            name='service_port_id_cache',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='configuredonu',
            name='user_vlan_cache',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='configuredonu',
            name='download_profile_index_cache',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='configuredonu',
            name='upload_profile_index_cache',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='configuredonu',
            name='download_profile_name_cache',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
        migrations.AddField(
            model_name='configuredonu',
            name='upload_profile_name_cache',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
    ]
