from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0044_olt_subscription_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="ONUTrafficSample",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("slot", models.PositiveIntegerField()),
                ("port", models.PositiveIntegerField()),
                ("ont_id", models.PositiveIntegerField()),
                ("up_bytes", models.BigIntegerField(default=0)),
                ("down_bytes", models.BigIntegerField(default=0)),
                ("up_packets", models.BigIntegerField(default=0)),
                ("down_packets", models.BigIntegerField(default=0)),
                ("up_bps", models.FloatField(default=0)),
                ("down_bps", models.FloatField(default=0)),
                ("sampled_at", models.DateTimeField(auto_now_add=True)),
                ("olt", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="onu_traffic_samples", to="oltmanager.olt")),
            ],
            options={
                "ordering": ["sampled_at"],
            },
        ),
        migrations.AddIndex(
            model_name="onutrafficsample",
            index=models.Index(fields=["olt", "slot", "port", "ont_id", "sampled_at"], name="onu_traffic_lookup_idx"),
        ),
    ]
