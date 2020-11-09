from rest_framework import serializers
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