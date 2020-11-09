from django.contrib import auth
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes, force_str, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .models import User


class RegisterSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(max_length=20, min_length=4, write_only=True)
    password2 = serializers.CharField(max_length=20, min_length=4, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password1', 'password2']

    def validate(self, attrs):
        email = attrs.get('email')
        username = attrs.get('username')
        pass1 = attrs.get('password1')
        pass2 = attrs.get('password2')

        if not username.isalnum():
            raise serializers.ValidationError('Username cannot contain Special Characters!')

        if pass1 != pass2:
            raise serializers.ValidationError("Passwords didn't matched!")

        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=512)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=20, min_length=4, write_only=True)
    username = serializers.CharField(max_length=20, read_only=True)
    tokens = serializers.CharField(max_length=512, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid User Credentials! please retry.')
        if not user.is_active:
            raise AuthenticationFailed('Sorry the account is deactivated!')
        if not user.is_verified:
            raise AuthenticationFailed('Email not verified!')

        context = {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens,
        }
        return context

        # return super().validate(attrs)


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password1 = serializers.CharField(max_length=20, min_length=4, write_only=True)
    password2 = serializers.CharField(max_length=20, min_length=4, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password1', 'password2', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            pass1 = attrs.get('password1')
            pass2 = attrs.get('password2')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            if pass1 != pass2:
                raise AuthenticationFailed("Passwords didn't matched!", 401)

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            # check whether the use of first time
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link invalid!', 401)

            user.set_password(pass1)
            user.save()

            return user

        except Exception as e:
            raise AuthenticationFailed(e, 401)


