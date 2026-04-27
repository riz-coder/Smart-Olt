from django.db import migrations, models
import django.db.models.deletion

class Migration(migrations.Migration):
    dependencies = [
        ('oltmanager', '0024_pontrafficsample'),
    ]

    operations = [
        migrations.CreateModel(
            name='PONPortTrafficSample',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('slot', models.PositiveIntegerField(default=0)),
                ('port', models.PositiveIntegerField(default=0)),
                ('in_octets', models.BigIntegerField(default=0)),
                ('out_octets', models.BigIntegerField(default=0)),
                ('in_packets', models.BigIntegerField(default=0)),
                ('out_packets', models.BigIntegerField(default=0)),
                ('sampled_at', models.DateTimeField(auto_now_add=True)),
                ('olt', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pon_port_traffic_samples', to='oltmanager.olt')),
            ],
            options={
                'ordering': ['sampled_at'],
                'indexes': [
                    models.Index(fields=['olt', 'slot', 'port', 'sampled_at'], name='pon_port_slot_time_idx'),
                    models.Index(fields=['olt', 'sampled_at'], name='pon_port_olt_time_idx'),
                ],
            },
        ),
    ]

