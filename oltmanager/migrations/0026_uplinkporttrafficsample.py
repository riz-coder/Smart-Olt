from django.db import migrations, models
import django.db.models.deletion

class Migration(migrations.Migration):
    dependencies = [
        ('oltmanager', '0025_ponporttrafficsample'),
    ]

    operations = [
        migrations.CreateModel(
            name='UplinkPortTrafficSample',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('port_name', models.CharField(max_length=64)),
                ('in_octets', models.BigIntegerField(default=0)),
                ('out_octets', models.BigIntegerField(default=0)),
                ('sampled_at', models.DateTimeField(auto_now_add=True)),
                ('olt', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='uplink_port_traffic_samples', to='oltmanager.olt')),
            ],
            options={
                'ordering': ['sampled_at'],
                'indexes': [
                    models.Index(fields=['olt', 'port_name', 'sampled_at'], name='uplk_port_time_idx'),
                    models.Index(fields=['olt', 'sampled_at'], name='uplk_olt_time_idx'),
                ],
            },
        ),
    ]
