from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('login/', views.user_login, name='login'),
    path('logout/',auth_views.LogoutView.as_view(), name='logout'),
    path("verify_otp/", views.verify_otp, name="verify_otp"),
    path('register/', views.register, name='register'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate')
]