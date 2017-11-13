from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='login_reg_app_index'),
    url(r'^register$', views.register, name='login_reg_app_register'),
    url(r'^login$', views.login, name='login_reg_app_login'),
    url(r'^logout$', views.logout, name='login_reg_app_logout'),
    url(r'^dashboard$', views.dashboard, name='login_reg_app_dashboard'),

]