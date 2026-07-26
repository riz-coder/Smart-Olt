from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", auth_views.LoginView.as_view(template_name="registration/control_login.html"), name="control_login"),
    path("logout/", auth_views.LogoutView.as_view(), name="control_logout"),
    path("", include("controlmanager.urls")),
]
