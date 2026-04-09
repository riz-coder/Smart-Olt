from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('oltmanager', '0005_olt_cards_cache_fields'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='OLTLoginHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(blank=True, default='', max_length=150)),
                ('action', models.CharField(default='login', max_length=50)),
                ('details', models.CharField(blank=True, default='', max_length=300)),
                ('logged_in_at', models.DateTimeField(auto_now_add=True)),
                ('olt', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='login_history', to='oltmanager.olt')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-logged_in_at'],
            },
        ),
    ]
