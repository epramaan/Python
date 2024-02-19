import code
from django.urls import path

from . import views

urlpatterns = [
    path('', views.signin, name='signin'),
    path('oidc_auth_code', views.oidc_auth_code, name='oidc_auth_code'),
    path('views/processAuthCodeAndGetToken', views.processAuthCodeAndGetToken, name='processAuthCodeAndGetToken'),
    path('onetimeverificationforuser', views.onetimeverificationforuser, name='onetimeverificationforuser'),  # type: ignore
    path('onetimepushback', views.onetimepushback, name='onetimepushback'),  # type: ignore
    path('logout', views.logout, name='logout')
]
