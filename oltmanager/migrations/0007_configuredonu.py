from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('oltmanager', '0006_oltloginhistory'),
    ]

    operations = [
        migrations.CreateModel(
            name='ConfiguredONU',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('frame', models.PositiveIntegerField(default=0)),
                ('slot', models.PositiveIntegerField()),
                ('port', models.PositiveIntegerField()),
                ('ont_id', models.PositiveIntegerField()),
                ('sn', models.CharField(blank=True, default='', max_length=64)),
                ('control_flag', models.CharField(blank=True, default='', max_length=32)),
                ('run_state', models.CharField(blank=True, default='', max_length=32)),
                ('config_state', models.CharField(blank=True, default='', max_length=32)),
                ('match_state', models.CharField(blank=True, default='', max_length=32)),
                ('protect_side', models.CharField(blank=True, default='', max_length=32)),
                ('description', models.CharField(blank=True, default='', max_length=255)),
                ('raw_line', models.TextField(blank=True, default='')),
                ('synced_at', models.DateTimeField(auto_now=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('olt', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='configured_onus', to='oltmanager.olt')),
            ],
            options={
                'ordering': ['olt_id', 'slot', 'port', 'ont_id'],
            },
        ),
        migrations.AddConstraint(
            model_name='configuredonu',
            constraint=models.UniqueConstraint(fields=('olt', 'frame', 'slot', 'port', 'ont_id'), name='unique_configured_onu_per_olt_port'),
        ),
    ]
