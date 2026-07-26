from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Sum
from django.shortcuts import get_object_or_404, redirect, render

from .forms import TenantCreateForm
from .models import ControlAuditLog, Tenant
from .services import (
    TenantProvisionError,
    TenantSnapshotError,
    delete_tenant_olt,
    delete_tenant_onu,
    get_tenant_olt_onus,
    get_tenant_olts,
    provision_tenant_instance,
    refresh_tenant_database_snapshot,
)


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
    tenants = Tenant.objects.select_related("plan").annotate(contact_count=Count("contacts")).order_by("name")
    return render(request, "controlmanager/tenant_list.html", {"tenants": tenants})


@login_required
@owner_required
def tenant_create(request):
    if request.method == "POST":
        form = TenantCreateForm(request.POST)
        if form.is_valid():
            tenant = form.save()
            try:
                result = provision_tenant_instance(tenant)
                audit(request, "tenant_provision", tenant, f"Tenant provisioned: {result.get('panel_url')}")
                messages.success(request, f"Tenant `{tenant.name}` created and started on {result.get('panel_url')}.")
            except TenantProvisionError as exc:
                tenant.status = Tenant.STATUS_PROVISIONING
                tenant.notes = f"{tenant.notes}\nProvisioning failed: {exc}".strip()
                tenant.save(update_fields=["status", "notes", "updated_at"])
                audit(request, "tenant_provision_failed", tenant, str(exc))
                messages.error(request, f"Tenant record created, but provisioning failed: {exc}")
            return redirect("control_tenant_detail", pk=tenant.pk)
    else:
        form = TenantCreateForm()
    return render(request, "controlmanager/tenant_create.html", {"form": form})


@login_required
@owner_required
def tenant_detail(request, pk):
    tenant = get_object_or_404(Tenant.objects.select_related("plan"), pk=pk)
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
        if action == "refresh_db":
            try:
                result = refresh_tenant_database_snapshot(tenant)
                audit(request, "tenant_db_refresh", tenant, f"DB-only refresh: {result['olt_count']} OLTs, {result['onu_count']} ONUs")
                messages.success(
                    request,
                    f"DB snapshot refreshed: {result['olt_count']} OLTs, {result['onu_count']} ONUs.",
                )
            except TenantSnapshotError as exc:
                audit(request, "tenant_db_refresh_failed", tenant, str(exc))
                messages.error(request, str(exc))
            return redirect("control_tenant_detail", pk=tenant.pk)
    tenant_olts = []
    tenant_olts_error = ""
    if tenant.database_path:
        try:
            tenant_olts = get_tenant_olts(tenant)
        except TenantSnapshotError as exc:
            tenant_olts_error = str(exc)
    context = {
        "tenant": tenant,
        "status_choices": Tenant.STATUS_CHOICES,
        "olt_snapshots": tenant.olt_snapshots.all(),
        "tenant_olts": tenant_olts,
        "tenant_olts_error": tenant_olts_error,
        "snapshots": tenant.snapshots.all()[:12],
        "logs": ControlAuditLog.objects.filter(tenant=tenant).select_related("user")[:20],
    }
    return render(request, "controlmanager/tenant_detail.html", context)


@login_required
@owner_required
def tenant_olt_detail(request, pk, tenant_olt_id):
    tenant = get_object_or_404(Tenant, pk=pk)
    try:
        olt, onus = get_tenant_olt_onus(tenant, tenant_olt_id)
    except TenantSnapshotError as exc:
        messages.error(request, str(exc))
        return redirect("control_tenant_detail", pk=tenant.pk)
    return render(request, "controlmanager/tenant_olt_detail.html", {"tenant": tenant, "olt": olt, "onus": onus})


@login_required
@owner_required
def tenant_olt_delete(request, pk, tenant_olt_id):
    tenant = get_object_or_404(Tenant, pk=pk)
    if request.method != "POST":
        return redirect("control_tenant_olt_detail", pk=tenant.pk, tenant_olt_id=tenant_olt_id)
    try:
        output = delete_tenant_olt(tenant, tenant_olt_id)
        audit(request, "tenant_olt_delete", tenant, output)
        messages.success(request, f"OLT deleted from tenant DB. {output}")
    except (TenantProvisionError, TenantSnapshotError) as exc:
        audit(request, "tenant_olt_delete_failed", tenant, str(exc))
        messages.error(request, str(exc))
    return redirect("control_tenant_detail", pk=tenant.pk)


@login_required
@owner_required
def tenant_onu_delete(request, pk, tenant_olt_id, onu_id):
    tenant = get_object_or_404(Tenant, pk=pk)
    if request.method != "POST":
        return redirect("control_tenant_olt_detail", pk=tenant.pk, tenant_olt_id=tenant_olt_id)
    try:
        output = delete_tenant_onu(tenant, onu_id)
        audit(request, "tenant_onu_delete", tenant, output)
        messages.success(request, f"ONU deleted from tenant DB. {output}")
    except (TenantProvisionError, TenantSnapshotError) as exc:
        audit(request, "tenant_onu_delete_failed", tenant, str(exc))
        messages.error(request, str(exc))
    return redirect("control_tenant_olt_detail", pk=tenant.pk, tenant_olt_id=tenant_olt_id)


@login_required
@owner_required
def plan_list(request):
    return render(request, "controlmanager/plan_list.html")


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
