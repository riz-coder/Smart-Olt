import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction


class Command(BaseCommand):
    help = "Create the initial tenant administrator without resetting an existing password."

    @transaction.atomic
    def handle(self, *args, **options):
        username = os.environ.get("OPTIVERSE_ADMIN_USERNAME", "admin").strip()
        email = os.environ.get("OPTIVERSE_ADMIN_EMAIL", "").strip()
        password = os.environ.get("OPTIVERSE_ADMIN_PASSWORD", "")
        if not username or not password:
            raise CommandError("OPTIVERSE_ADMIN_USERNAME and OPTIVERSE_ADMIN_PASSWORD are required.")

        User = get_user_model()
        user, created = User.objects.get_or_create(
            username=username,
            defaults={"email": email, "is_staff": True, "is_superuser": True},
        )
        update_fields = []
        if not user.is_staff:
            user.is_staff = True
            update_fields.append("is_staff")
        if not user.is_superuser:
            user.is_superuser = True
            update_fields.append("is_superuser")
        if created:
            user.set_password(password)
            update_fields.append("password")
        if created and email != user.email:
            user.email = email
            update_fields.append("email")
        if update_fields:
            user.save(update_fields=list(dict.fromkeys(update_fields)))
        self.stdout.write("Tenant administrator created." if created else "Tenant administrator already exists.")
