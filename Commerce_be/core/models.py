from django.db import models

# Create your models here.
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
    username = models.CharField(max_length=150)
    email_address = models.EmailField(unique=True)

    provider = models.CharField(
        max_length=20,
        choices=REGISTRATION_PROVIDERS,
        default='email'
    )

    uid = models.CharField(max_length=255, null=True, blank=True)  # Firebase/social UID
    photo_url = models.URLField(max_length=500, null=True, blank=True)  # profile picture

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
    REQUIRED_FIELDS = ['firstname', 'lastname']

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.firstname} {self.lastname} ({self.email_address})"


    @property
    @extend_schema_field(str)
    def full_name(self):
        """Return user's full name by combining first and last name"""
        return f"{self.firstname} {self.lastname}".strip()

    @property
    @extend_schema_field(bool)
    def is_verified(self):
        """Return True if user account is verified, False otherwise"""
        return self.verified_at is not None
    
    def validate_for_login(self):
        """
        Validate user can login - checks active status and verification
        Raises ValidationError with specific message if validation fails
        """
        if not self.is_active:
            raise ValidationError('Account is disabled')
        
        if not self.is_verified:
            raise ValidationError('Account not verified')
        
        return True

    def generate_verification_code(self):
        """Generate a 6-digit verification code"""
        import random
        self.verification_code = str(random.randint(100000, 999999))
        # Set expiration to 10 minutes from now
        self.verification_code_expires_at = timezone.now() + timedelta(minutes=20)
        self.save(update_fields=['verification_code', 'verification_code_expires_at'])

    def verify_code(self, code):
        """Verify the provided code"""
        if (self.verification_code == code and 
            self.verification_code_expires_at and 
            timezone.now() <= self.verification_code_expires_at):
            self.verified_at = timezone.now()
            self.verification_code = None
            self.verification_code_expires_at = None
            self.save(update_fields=['verified_at', 'verification_code', 'verification_code_expires_at'])
            return True
        return False

    def generate_password_reset_token(self):
        """Generate secure reset token with rate limiting"""
        now = timezone.now()
        
        # Check if user is temporarily blocked
        if self.password_reset_blocked_until and now < self.password_reset_blocked_until:
            raise ValidationError("Too many reset attempts. Try again later.")
        
        # Generate cryptographically secure token
        self.password_reset_token = secrets.token_urlsafe(48)
        self.password_reset_expires_at = now + timedelta(hours=1)  # 1 hour expiry
        self.password_reset_attempts = 0
        self.password_reset_blocked_until = None
        self.save(update_fields=['password_reset_token', 'password_reset_expires_at', 
                               'password_reset_attempts', 'password_reset_blocked_until'])
        return self.password_reset_token

    def verify_password_reset_token(self, token):
        """Verify token with rate limiting and security checks"""
        now = timezone.now()
        
        # Check if blocked
        if self.password_reset_blocked_until and now < self.password_reset_blocked_until:
            return False, "Too many attempts. Try again later."
        
        # Check token validity
        if not self.password_reset_token or not self.password_reset_expires_at:
            return False, "Invalid reset token"
        
        # Check expiration
        if now > self.password_reset_expires_at:
            self.clear_password_reset_token()
            return False, "Reset token has expired"
        
        # Check token match (constant-time comparison for security)
        if not secrets.compare_digest(self.password_reset_token, token):
            self.increment_reset_attempts()
            return False, "Invalid reset token"
        
        return True, "Token valid"

    def increment_reset_attempts(self):
        """Track failed attempts and implement rate limiting"""
        self.password_reset_attempts += 1
        
        # Block after 5 failed attempts for 30 minutes
        if self.password_reset_attempts >= 5:
            self.password_reset_blocked_until = timezone.now() + timedelta(minutes=30)
            self.clear_password_reset_token()
        
        self.save(update_fields=['password_reset_attempts', 'password_reset_blocked_until'])

    def reset_password(self, new_password):
        """Reset password and clear all reset data"""
        self.set_password(new_password)
        self.clear_password_reset_token()
        # Invalidate all existing sessions/tokens for security
        self.last_login = timezone.now()
        self.save()

    def clear_password_reset_token(self):
        """Clear all password reset related fields"""
        self.password_reset_token = None
        self.password_reset_expires_at = None
        self.password_reset_attempts = 0
        self.password_reset_blocked_until = None
        self.save(update_fields=['password_reset_token', 'password_reset_expires_at',
                               'password_reset_attempts', 'password_reset_blocked_until'])
