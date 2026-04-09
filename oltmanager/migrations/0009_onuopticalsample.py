from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0008_configuredonu_optical_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="ONUOpticalSample",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("slot", models.PositiveIntegerField()),
                ("port", models.PositiveIntegerField()),
                ("ont_id", models.PositiveIntegerField()),
                ("onu_rx", models.CharField(blank=True, default="", max_length=32)),
                ("olt_rx", models.CharField(blank=True, default="", max_length=32)),
                ("tx_power", models.CharField(blank=True, default="", max_length=32)),
                ("sampled_at", models.DateTimeField(auto_now_add=True)),
                ("olt", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="onu_optical_samples", to="oltmanager.olt")),
            ],
            options={
                "ordering": ["sampled_at"],
            },
        ),
        migrations.AddIndex(
            model_name="onuopticalsample",
            index=models.Index(fields=["olt", "slot", "port", "ont_id", "sampled_at"], name="onu_sample_lookup_idx"),
        ),
    ]
