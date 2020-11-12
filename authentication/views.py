from django.shortcuts import render
from rest_framework import generics, status, views
from rest_framework.response import Response
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer, PasswordResetSerializer, SetNewPasswordSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes, force_str, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import jwt


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data

        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relative_link = reverse('verify-email')  # goto email-verify/ path
        absolute_url = 'http://' + current_site + relative_link + '?token=' + str(token)
        email_body = "Hi " + user.username + "Use bellow link to verify your email\n" + absolute_url

        data = {
            'receiver': user.email,
            'email_body': email_body,
            'email_subject': 'Verify your Email',
        }

        Util.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()

            context = {
                "email": "Successfully Activated!",
            }

            return Response(context, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as identifier:
            context = {
                "error": "Activation Token Expired!"
            }

            return Response(context, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError as identifier:
            context = {
                "error": "Invalid Token",
            }

            return Response(context, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class PasswordResetAPIView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)

            current_site = get_current_site(request=request).domain
            relative_link = reverse('password-reset-token-check', kwargs={'uidb64':uidb64, 'token': token})  # goto email-verify/ path
            absolute_url = 'http://' + current_site + relative_link
            email_body = "Hi \nUse bellow link to reset your password\n" + absolute_url

            data = {
                'receiver': user.email,
                'email_body': email_body,
                'email_subject': 'Reset your password',
            }

            Util.send_email(data)

        context = {
            'msg': 'Password reset email was sent',
        }

        return Response(context, status=status.HTTP_200_OK)


class PasswordTokenCheckAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            context = {
                'success': True,
                'msg': 'Credentials Valid',
                'uidb64': uidb64,
                'token': token,
            }

            # check whether the use of first time
            # if PasswordResetTokenGenerator().check_token(user, token):
            #     return Response({'error': 'Token is not Expired!'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response(context, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'error': 'Token is not valid anymore!'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        context = {
            'success': True, 'msg': 'Password Reset Success!'
        }

        return Response(context, status=status.HTTP_200_OK)


