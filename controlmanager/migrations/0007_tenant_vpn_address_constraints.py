from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('controlmanager', '0006_tenant_public_hostname_tenant_subdomain_and_more')]

    operations = [
        migrations.AddConstraint(
            model_name='tenant',
            constraint=models.UniqueConstraint(
                fields=('vpn_server_address',),
                condition=~models.Q(vpn_server_address=''),
                name='unique_nonempty_vpn_server_address',
            ),
        ),
        migrations.AddConstraint(
            model_name='tenant',
            constraint=models.UniqueConstraint(
                fields=('wg_client_address',),
                condition=~models.Q(wg_client_address=''),
                name='unique_nonempty_wg_client_address',
            ),
        ),
    ]
