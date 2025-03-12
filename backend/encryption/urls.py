from django.urls import path
from . import views

app_name = "encryption"

urlpatterns = [
    path("", views.index, name="index"),
]