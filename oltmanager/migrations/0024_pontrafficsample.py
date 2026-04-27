from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0023_olt_autofind_category_counts"),
    ]

    operations = [
        migrations.CreateModel(
            name="PONTrafficSample",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("in_octets", models.BigIntegerField(default=0)),
                ("out_octets", models.BigIntegerField(default=0)),
                ("in_packets", models.BigIntegerField(default=0)),
                ("out_packets", models.BigIntegerField(default=0)),
                ("sampled_at", models.DateTimeField(auto_now_add=True)),
                ("olt", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="pon_traffic_samples", to="oltmanager.olt")),
            ],
            options={
                "ordering": ["sampled_at"],
            },
        ),
        migrations.AddIndex(
            model_name="pontrafficsample",
            index=models.Index(fields=["olt", "sampled_at"], name="pon_traffic_olt_time_idx"),
        ),
        migrations.AddIndex(
            model_name="pontrafficsample",
            index=models.Index(fields=["sampled_at"], name="pon_traffic_time_idx"),
        ),
    ]
