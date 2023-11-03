from django.urls import path
from . import views

urlpatterns = [
    path('accounts/register/', views.register, name='register'),
    path('accounts/login/', views.login, name='login'),
    path('accounts/profile/view/', views.view_profile, name='view_profile'),
    path('accounts/profile/edit/', views.edit_profile, name='edit_profile'),
]
