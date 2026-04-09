from django.urls import re_path

from .consumers import OLTCLIConsumer


websocket_urlpatterns = [
    re_path(r"^ws/olt/(?P<pk>\d+)/cli/$", OLTCLIConsumer.as_asgi()),
]
