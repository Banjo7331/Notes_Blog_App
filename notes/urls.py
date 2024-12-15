from django.urls import path
from . import views

urlpatterns = [
    path('profile/<str:username>/', views.profile_view, name='profile'),
    path('like/<int:note_id>/', views.LikeView, name='like_note'),
    path('follow/<int:user_id>/', views.FallowView, name='user_follow'),
    path('', views.dashboard, name='dashboard'),
]