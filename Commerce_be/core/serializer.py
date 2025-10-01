from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import User
from django.utils import timezone
from django.db import IntegrityError

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = [
            'name',           
            'country_code',
            'phone_number',   
            'email_address',
            'password',
            'password_confirm',
        ]

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm', None)
        user = User.objects.create_user(**validated_data)
        return user


class SocialRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'name',     
            'email_address',
            'provider',
            'uid',
            'photo_url',
        ]
        extra_kwargs = {
            'email_address': {'validators': []}
        }

    def validate_email_address(self, value):
        provider = self.initial_data.get('provider')
        if provider == 'email' and User.objects.filter(email_address=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        provider = validated_data.get('provider')
        email = validated_data.get('email_address')
        user = User.objects.filter(email_address=email).first()
        if user:
            if user.provider != provider:
                raise serializers.ValidationError(
                    f"User is registered with {user.provider.capitalize()}, not {provider.capitalize()}."
                )
            return user
        try:
            user = User.objects.create_user(
                **validated_data,
                provider=provider,
                is_active=True
            )
            user.verified_at = timezone.now()
            user.save()
            return user
        except IntegrityError:
            raise serializers.ValidationError("Failed to create user due to a conflict.")

class UserLoginSerializer(serializers.Serializer):
    email_address = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.ReadOnlyField()
    is_verified = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'full_name',
            'email_address',
            'name',
            'account_type',
            'country',
            'country_code',
            'state',
            'address',
            'phone_number',
            'is_verified',
            'verified_at',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'verified_at', 'created_at', 'updated_at']


class AccountVerificationSerializer(serializers.Serializer):
    email_address = serializers.EmailField()
    verification_code = serializers.CharField(max_length=10)


class PasswordResetRequestSerializer(serializers.Serializer):
    email_address = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=64)  # Increased for security
    new_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def validate_new_password(self, value):
        """Validate password strength"""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate(self, attrs):
        """Validate passwords match"""
        if attrs['new_password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Passwords don't match"})
        return attrs
