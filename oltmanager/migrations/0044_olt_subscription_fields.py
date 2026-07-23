import calendar
import datetime

from django.db import migrations, models


def add_months(start_date, months):
    month_index = start_date.month - 1 + int(months or 1)
    year = start_date.year + month_index // 12
    month = month_index % 12 + 1
    day = min(start_date.day, calendar.monthrange(year, month)[1])
    return datetime.date(year, month, day)


def seed_subscription_dates(apps, schema_editor):
    OLT = apps.get_model("oltmanager", "OLT")
    for olt in OLT.objects.all():
        started_at = None
        if olt.created_at:
            started_at = olt.created_at.date()
        started_at = started_at or datetime.date.today()
        package_months = int(olt.subscription_package_months or 1)
        olt.subscription_started_at = started_at
        olt.subscription_ends_at = add_months(started_at, package_months)
        olt.save(update_fields=["subscription_started_at", "subscription_ends_at"])


class Migration(migrations.Migration):

    dependencies = [
        ("oltmanager", "0043_expand_configuredonu_service_profile_caches"),
    ]

    operations = [
        migrations.AddField(
            model_name="olt",
            name="subscription_package_months",
            field=models.PositiveSmallIntegerField(
                choices=[(1, "1 Month"), (3, "3 Months"), (6, "6 Months")],
                default=1,
            ),
        ),
        migrations.AddField(
            model_name="olt",
            name="subscription_started_at",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="olt",
            name="subscription_ends_at",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.RunPython(seed_subscription_dates, migrations.RunPython.noop),
    ]
