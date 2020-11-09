from django.urls import path
from .views import RegisterView, VerifyEmail, LoginAPIView, PasswordTokenCheckAPIView, PasswordResetAPIView


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('verify-email/', VerifyEmail.as_view(), name='verify-email'),
    path('password-reset-email', PasswordResetAPIView.as_view(), name="password-reset-email" ),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPIView.as_view(), name='password-reset-confirm'),
]