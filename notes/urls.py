from django.urls import path
from . import views

urlpatterns = [
    path('sent-notes-box/', views.sent_notes_box, name='sent_notes_box'),
    path('decrypt-note/<uuid:note_id>/', views.decrypt_note, name='decrypt_note'),
    path('profile/<str:username>/', views.profile_view, name='profile'),
    path('like/<uuid:note_id>/', views.LikeView, name='like_note'),
    path('follow/<uuid:user_id>/', views.FallowView, name='user_follow'),
    path('', views.dashboard, name='dashboard'),
]