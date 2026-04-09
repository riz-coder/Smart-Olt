from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oltmanager', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='olt',
            name='port',
            field=models.IntegerField(default=23, help_text='Telnet port'),
        ),
    ]
