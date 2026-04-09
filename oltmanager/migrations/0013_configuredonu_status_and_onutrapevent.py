from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0012_olt_uplink_cache"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuredonu",
            name="derived_status",
            field=models.CharField(blank=True, db_index=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="status_source",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="configuredonu",
            name="status_updated_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="ONUTrapEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("slot", models.PositiveIntegerField()),
                ("port", models.PositiveIntegerField()),
                ("ont_id", models.PositiveIntegerField()),
                ("alarm_key", models.CharField(max_length=96)),
                ("alarm_code", models.CharField(blank=True, default="", max_length=64)),
                ("alarm_name", models.CharField(blank=True, default="", max_length=255)),
                ("mapped_status", models.CharField(blank=True, db_index=True, default="", max_length=32)),
                ("severity", models.CharField(blank=True, default="", max_length=32)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                ("raw_payload", models.TextField(blank=True, default="")),
                ("first_seen", models.DateTimeField(auto_now_add=True)),
                ("last_seen", models.DateTimeField(auto_now=True)),
                ("olt", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="onu_trap_events", to="oltmanager.olt")),
            ],
            options={
                "ordering": ["-last_seen"],
                "indexes": [
                    models.Index(fields=["olt", "slot", "port", "ont_id", "is_active"], name="onu_trap_active_lookup_idx"),
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="onutrapevent",
            constraint=models.UniqueConstraint(fields=("olt", "slot", "port", "ont_id", "alarm_key"), name="unique_onu_trap_event_per_alarm"),
        ),
    ]
