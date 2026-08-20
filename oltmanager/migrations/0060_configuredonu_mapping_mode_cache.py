from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oltmanager', '0059_onuopticalsample_sample_source'),
    ]

    operations = [
        migrations.AddField(
            model_name='configuredonu',
            name='mapping_mode_cache',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
    ]
