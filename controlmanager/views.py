from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Sum
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .forms import PlanForm, TenantContactForm, TenantForm, TenantSnapshotForm
from .models import ControlAuditLog, Plan, Tenant, TenantContact, TenantSnapshot


def owner_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not bool(request.user and request.user.is_authenticated and request.user.is_superuser):
            raise PermissionDenied("Control plane owner access is required.")
        return view_func(request, *args, **kwargs)
    return _wrapped


def audit(request, action, tenant=None, details=""):
    try:
        ControlAuditLog.objects.create(
            action=str(action or "")[:80],
            tenant=tenant,
            user=request.user if request.user.is_authenticated else None,
            details=str(details or "")[:300],
        )
    except Exception:
        pass


@login_required
@owner_required
def dashboard(request):
    tenants = Tenant.objects.select_related("plan")
    totals = tenants.aggregate(
        total_olts=Sum("last_known_olt_count"),
        total_onus=Sum("last_known_onu_count"),
        total_db_mb=Sum("last_known_db_size_mb"),
    )
    context = {
        "tenants_count": tenants.count(),
        "active_count": tenants.filter(status=Tenant.STATUS_ACTIVE).count(),
        "suspended_count": tenants.filter(status=Tenant.STATUS_SUSPENDED).count(),
        "disabled_count": tenants.filter(status=Tenant.STATUS_DISABLED).count(),
        "provisioning_count": tenants.filter(status=Tenant.STATUS_PROVISIONING).count(),
        "total_olts": totals.get("total_olts") or 0,
        "total_onus": totals.get("total_onus") or 0,
        "total_db_mb": totals.get("total_db_mb") or 0,
        "recent_tenants": tenants.order_by("-updated_at")[:8],
        "recent_logs": ControlAuditLog.objects.select_related("tenant", "user")[:20],
    }
    return render(request, "controlmanager/dashboard.html", context)


@login_required
@owner_required
def tenant_list(request):
    if request.method == "POST":
        form = TenantForm(request.POST)
        if form.is_valid():
            tenant = form.save()
            audit(request, "tenant_create", tenant, f"Tenant created: {tenant.name}")
            messages.success(request, f"Tenant `{tenant.name}` created.")
            return redirect("control_tenant_detail", pk=tenant.pk)
    else:
        form = TenantForm(initial={"panel_scheme": "http", "panel_port": 8000})

    tenants = Tenant.objects.select_related("plan").annotate(contact_count=Count("contacts")).order_by("name")
    return render(request, "controlmanager/tenant_list.html", {"form": form, "tenants": tenants})


@login_required
@owner_required
def tenant_detail(request, pk):
    tenant = get_object_or_404(Tenant.objects.select_related("plan"), pk=pk)
    form = TenantForm(instance=tenant)
    contact_form = TenantContactForm()
    snapshot_form = TenantSnapshotForm(initial={
        "olt_count": tenant.last_known_olt_count,
        "onu_count": tenant.last_known_onu_count,
        "db_size_mb": tenant.last_known_db_size_mb,
    })
    if request.method == "POST":
        action = str(request.POST.get("action") or "update").strip().lower()
        if action == "status":
            new_status = str(request.POST.get("status") or "").strip()
            valid = {choice[0] for choice in Tenant.STATUS_CHOICES}
            if new_status not in valid:
                messages.error(request, "Invalid tenant status.")
            else:
                old_status = tenant.status
                tenant.status = new_status
                tenant.save(update_fields=["status", "updated_at"])
                audit(request, "tenant_status", tenant, f"Status changed {old_status} -> {new_status}")
                messages.success(request, f"Tenant status updated to {tenant.get_status_display()}.")
            return redirect("control_tenant_detail", pk=tenant.pk)
        if action == "snapshot":
            snapshot_form = TenantSnapshotForm(request.POST)
            if snapshot_form.is_valid():
                snapshot = snapshot_form.save(commit=False)
                snapshot.tenant = tenant
                snapshot.save()
                tenant.last_known_olt_count = snapshot.olt_count
                tenant.last_known_onu_count = snapshot.onu_count
                tenant.last_known_db_size_mb = snapshot.db_size_mb
                tenant.last_reported_at = timezone.now()
                tenant.save(update_fields=[
                    "last_known_olt_count", "last_known_onu_count", "last_known_db_size_mb",
                    "last_reported_at", "updated_at",
                ])
                audit(request, "tenant_snapshot", tenant, "Manual resource snapshot updated")
                messages.success(request, "Tenant resource snapshot saved.")
                return redirect("control_tenant_detail", pk=tenant.pk)
            messages.error(request, "Snapshot could not be saved.")
        if action == "contact":
            contact_form = TenantContactForm(request.POST)
            if contact_form.is_valid():
                contact = contact_form.save(commit=False)
                contact.tenant = tenant
                contact.save()
                audit(request, "tenant_contact", tenant, f"Contact added: {contact.name}")
                messages.success(request, f"Contact `{contact.name}` added.")
                return redirect("control_tenant_detail", pk=tenant.pk)
            messages.error(request, "Contact could not be saved.")
        if action == "update":
            form = TenantForm(request.POST, instance=tenant)
            if form.is_valid():
                tenant = form.save()
                audit(request, "tenant_update", tenant, f"Tenant updated: {tenant.name}")
                messages.success(request, f"Tenant `{tenant.name}` updated.")
                return redirect("control_tenant_detail", pk=tenant.pk)
            messages.error(request, "Tenant could not be updated.")
    context = {
        "tenant": tenant,
        "form": form,
        "contact_form": contact_form,
        "snapshot_form": snapshot_form,
        "status_choices": Tenant.STATUS_CHOICES,
        "contacts": tenant.contacts.all(),
        "snapshots": tenant.snapshots.all()[:12],
        "logs": ControlAuditLog.objects.filter(tenant=tenant).select_related("user")[:20],
    }
    return render(request, "controlmanager/tenant_detail.html", context)


@login_required
@owner_required
def plan_list(request):
    if request.method == "POST":
        form = PlanForm(request.POST)
        if form.is_valid():
            plan = form.save()
            audit(request, "plan_create", details=f"Plan created: {plan.name}")
            messages.success(request, f"Plan `{plan.name}` created.")
            return redirect("control_plans")
    else:
        form = PlanForm()
    plans = Plan.objects.annotate(tenant_count=Count("tenants")).order_by("monthly_price", "name")
    return render(request, "controlmanager/plan_list.html", {"form": form, "plans": plans})


@login_required
@owner_required
def tenant_delete(request, pk):
    tenant = get_object_or_404(Tenant, pk=pk)
    if request.method != "POST":
        return redirect("control_tenant_detail", pk=tenant.pk)
    name = tenant.name
    tenant.delete()
    audit(request, "tenant_delete", details=f"Tenant deleted from control DB only: {name}")
    messages.success(request, f"Tenant `{name}` deleted from control DB. Tenant app/database was not touched.")
    return redirect("control_tenants")
