from django.urls import path
from . import views

app_name = "encryption"

urlpatterns = [
    path("", views.index, name="index"),
    path("encrypt/", views.encrypt_view, name="encrypt"),
    path("decrypt/", views.decrypt_view, name="decrypt"),
    path("generate-password/", views.generate_password_view, name="generate-password"),
    path("generate-iv/", views.generate_iv_view, name="generate-iv"),
]