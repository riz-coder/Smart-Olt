from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="control_dashboard"),
    path("tenants/", views.tenant_list, name="control_tenants"),
    path("tenants/<int:pk>/", views.tenant_detail, name="control_tenant_detail"),
    path("tenants/<int:pk>/delete/", views.tenant_delete, name="control_tenant_delete"),
    path("plans/", views.plan_list, name="control_plans"),
]
