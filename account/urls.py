from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    # path('login/', views.user_login, name='login'),
    path('login/',views.OTPLoginView.as_view(), name='login'),
    path('logout/',auth_views.LogoutView.as_view(), name='logout'),
    path("otp/", views.otp_view, name="otp"),
    path('', views.dashboard, name='dashboard'),
    path('password_change/',auth_views.PasswordChangeView.as_view(), name='password_change'),
    path('password_change_done/',auth_views.PasswordChangeDoneView.as_view(), name='password_change_done'),
]