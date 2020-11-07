from django.urls import path
from knox import views as knox_views
from . import views

urlpatterns = [
    path('register/', views.RegisterApi.as_view(), name='register'),
    path('login/', views.LoginApi.as_view(), name='login'),
    path('logout/', knox_views.LogoutView.as_view(), name=''),
]
