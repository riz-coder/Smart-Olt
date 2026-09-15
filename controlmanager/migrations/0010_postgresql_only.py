from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('controlmanager', '0009_tenant_database_engine_tenant_database_host_and_more')]
    operations = [migrations.AlterField(
        model_name='tenant', name='database_engine',
        field=models.CharField(max_length=16, default='postgresql', choices=[('postgresql', 'PostgreSQL')]))]
