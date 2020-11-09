from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):
    def create_user(self, username, email, password1=None):
        if username is None:
            raise TypeError('User need to have username!')
        if email is None:
            raise TypeError('User need to have Email!')

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password1)
        user.save()
        return user

    def create_superuser(self, username, email, password):
        if password is None:
            raise TypeError("Password shouldn't be None!")

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)  # email verified?
    is_active = models.BooleanField(default=True)  # is user active?
    is_staff = models.BooleanField(default=False)  # is user in staff?
    created_at = models.DateTimeField(auto_now_add=True)  # registered date
    updated_at = models.DateTimeField(auto_now_add=True)  # last update date

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refreshtkn = RefreshToken.for_user(self)

        context = {
            'refresh': str(refreshtkn),
            'access': str(refreshtkn.access_token),
        }

        return context
