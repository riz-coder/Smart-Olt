from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('oltmanager', '0045_onutrafficsample'),
    ]

    operations = [
        migrations.CreateModel(
            name='ONUStatusSample',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('slot', models.PositiveIntegerField()),
                ('port', models.PositiveIntegerField()),
                ('ont_id', models.PositiveIntegerField()),
                ('status', models.CharField(db_index=True, max_length=32)),
                ('source', models.CharField(blank=True, default='', max_length=32)),
                ('sampled_at', models.DateTimeField(auto_now_add=True)),
                ('olt', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='onu_status_samples', to='oltmanager.olt')),
            ],
            options={
                'ordering': ['sampled_at'],
            },
        ),
        migrations.AddIndex(
            model_name='onustatussample',
            index=models.Index(fields=['olt', 'slot', 'port', 'ont_id', 'sampled_at'], name='onu_status_lookup_idx'),
        ),
    ]
