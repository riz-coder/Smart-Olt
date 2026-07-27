from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="control_dashboard"),
    path("tenants/", views.tenant_list, name="control_tenants"),
    path("tenants/create/", views.tenant_create, name="control_tenant_create"),
    path("tenants/<int:pk>/", views.tenant_detail, name="control_tenant_detail"),
    path("tenants/<int:pk>/olts/<int:tenant_olt_id>/", views.tenant_olt_detail, name="control_tenant_olt_detail"),
    path("tenants/<int:pk>/olts/<int:tenant_olt_id>/pricing/", views.tenant_olt_pricing_update, name="control_tenant_olt_pricing"),
    path("tenants/<int:pk>/olts/<int:tenant_olt_id>/delete/", views.tenant_olt_delete, name="control_tenant_olt_delete"),
    path("tenants/<int:pk>/olts/<int:tenant_olt_id>/onus/<int:onu_id>/delete/", views.tenant_onu_delete, name="control_tenant_onu_delete"),
    path("tenants/<int:pk>/delete/", views.tenant_delete, name="control_tenant_delete"),
    path("plans/", views.plan_list, name="control_plans"),
]
