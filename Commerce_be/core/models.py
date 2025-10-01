from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _
import uuid
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from datetime import timedelta
import secrets
from django.core.exceptions import ValidationError
from drf_spectacular.utils import extend_schema_field

class CustomUserManager(BaseUserManager):
    def create_user(self, email_address, password=None, **extra_fields):
        if not email_address:
            raise ValueError('The Email field must be set')

        email_address = self.normalize_email(email_address)
        user = self.model(email_address=email_address, **extra_fields)

        if password:
            user.set_password(password)

        user.save(using=self._db)
        return user

    def create_superuser(self, email_address, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('provider', 'email')
        extra_fields.setdefault('verified_at', timezone.now())

        if not password:
            raise ValueError('Superuser must have a password')

        return self.create_user(email_address, password, **extra_fields)


REGISTRATION_PROVIDERS = [
        ('email', 'Email Registration'),
        ('google', 'Google OAuth'),
        ('facebook', 'Facebook OAuth'),
        ('x', 'X OAuth'),
    ]


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Existing fields
    username = models.CharField(max_length=150)
    email_address = models.EmailField(unique=True)

    provider = models.CharField(
        max_length=20,
        choices=REGISTRATION_PROVIDERS,
        default='email'
    )

    uid = models.CharField(max_length=255, null=True, blank=True)  
    photo_url = models.URLField(max_length=500, null=True, blank=True)  

    
    name = models.CharField(max_length=255)  
    account_type = models.CharField(
        max_length=20,
        choices=[
            ('user', 'User'),
            ('admin', 'Admin'),
        ],
        default='user'
    )
    country = models.CharField(max_length=100, null=True, blank=True)
    country_code = models.CharField(max_length=10, null=True, blank=True)
    state = models.CharField(max_length=100, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)

    verification_code = models.CharField(max_length=10, null=True, blank=True)
    verification_code_expires_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)

    # Password reset fields
    password_reset_token = models.CharField(max_length=100, null=True, blank=True)
    password_reset_expires_at = models.DateTimeField(null=True, blank=True)
    password_reset_attempts = models.PositiveIntegerField(default=0)
    password_reset_blocked_until = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='created_users')
    updated_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='updated_users')

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email_address'
    REQUIRED_FIELDS = ['name', 'account_type']

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.name} ({self.email_address})"

    @property
    @extend_schema_field(str)
    def full_name(self):
        """Return user's full name (alias for name field)"""
        return self.name

