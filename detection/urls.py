from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.register_view, name='register'),
    path("predict/", views.predict_view, name="predict"),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path("verify/<str:token>/", views.verify_user, name="verify"),
    path("history/", views.history_view, name="history"),
    path("delete-log/<int:id>/", views.delete_log, name="delete_log"),
    path("download-logs/", views.download_logs, name="download_logs"),
    path("chatbot/", views.chatbot_page, name="chatbot"),
    path("chatbot-api/", views.chatbot_api, name="chatbot_api"),
    path("block-ip/<str:ip>/", views.block_ip, name="block_ip"),
    path("unblock-ip/<str:ip>/", views.unblock_ip, name="unblock_ip"),
    path("access-denied/", views.access_denied, name="access_denied"),
]
