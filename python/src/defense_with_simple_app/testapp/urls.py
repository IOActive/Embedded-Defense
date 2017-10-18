from django.conf.urls import url, patterns
from .views import test_form
from testapp import views

urlpatterns = [
	url(r'create_test_form/', views.test_form, name="test_form"),
]
