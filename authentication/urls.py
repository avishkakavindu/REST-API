from django.urls import path
from .views import RegisterView, VerifyEmail, LoginAPIView


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('verify-email/', VerifyEmail.as_view(), name='verify-email'),
]