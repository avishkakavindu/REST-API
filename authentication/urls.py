from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView,
    VerifyEmail,
    LoginAPIView,
    PasswordTokenCheckAPIView,
    PasswordResetAPIView,
    SetNewPasswordAPIView,
    SetProfilePictureAPIView,
)


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('verify-email/', VerifyEmail.as_view(), name='verify-email'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password-reset-email', PasswordResetAPIView.as_view(), name="password-reset-email" ),
    path('password-reset-token-check/<uidb64>/<token>/', PasswordTokenCheckAPIView.as_view(), name='password-reset-token-check'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
    path('set-profile-picture', SetProfilePictureAPIView.as_view(), name='set-profile-picture')
]