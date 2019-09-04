from django.conf.urls import url
from .views import reg, login

urlpatterns = [
    url(r"^reg$", reg),
    url(r"^login$",login)
]