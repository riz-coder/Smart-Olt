from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("oltmanager", "0066_olt_licence_fields"),
    ]

    operations = [
        migrations.AlterField(
            model_name="olt",
            name="licence_status",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="legacy",
                max_length=32,
            ),
        ),
    ]
