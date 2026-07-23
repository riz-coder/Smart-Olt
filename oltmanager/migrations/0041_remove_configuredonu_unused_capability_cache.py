from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0040_olt_onboarding_fields"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="configuredonu",
            name="catv_uni_ports_cache",
        ),
        migrations.RemoveField(
            model_name="configuredonu",
            name="eth_ports_cache",
        ),
        migrations.RemoveField(
            model_name="configuredonu",
            name="onu_type_cache",
        ),
        migrations.RemoveField(
            model_name="configuredonu",
            name="pots_ports_cache",
        ),
        migrations.RemoveField(
            model_name="configuredonu",
            name="uplink_pon_ports_cache",
        ),
    ]
