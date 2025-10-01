from urllib import response
from django.shortcuts import render
from core.serializer import AccountVerificationSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer, SocialRegistrationSerializer, UserLoginSerializer, UserRegistrationSerializer, UserSerializer
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from drf_spectacular.utils import extend_schema, extend_schema_view
from .custom_response import custom_response, custom_error_response
from .models import User

from .utils import send_verification_email, send_password_reset_email

from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError

from django.http import JsonResponse
from django.conf import settings
from rest_framework.response import Response
from django.db import IntegrityError
import logging

from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit
from rest_framework.views import APIView


logger = logging.getLogger(__name__)


@extend_schema_view(
    list=extend_schema(tags=['User Management']),
    retrieve=extend_schema(tags=['User Management']),
    create=extend_schema(tags=['User Management']),
    update=extend_schema(tags=['User Management']),
    partial_update=extend_schema(tags=['User Management']),
    destroy=extend_schema(tags=['User Management']),
)
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.action in ['register', 'login', 'forgot_password', 'reset_password', 'verify', 'resend_verification', 'social_register']:
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsAuthenticated]
        
        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        if self.action == 'register':
            return UserRegistrationSerializer
        elif self.action == 'social_register':
            return SocialRegistrationSerializer
        elif self.action == 'login':
            return UserLoginSerializer
        elif self.action == 'verify':
            return AccountVerificationSerializer
        elif self.action == 'forgot_password':
            return PasswordResetRequestSerializer
        elif self.action == 'reset_password':
            return PasswordResetConfirmSerializer
        return UserSerializer

    @extend_schema(
        tags=['Authentication'],
        description="Register or login user with social OAuth provider (Google, Facebook, etc.)."
    )
    @action(detail=False, methods=['post'], url_path='social-register')
    def social_register(self, request):
        serializer = SocialRegistrationSerializer(data=request.data, context={'is_social_register': True})
        if serializer.is_valid():
            email = serializer.validated_data.get('email_address')
            user = User.objects.filter(email_address=email).first()
            if user:
                success_message = f'Successfully logged in with {user.provider.capitalize()}!'
            else:
                user = serializer.save()
                success_message = f'Successfully signed up with {user.provider.capitalize()}!'

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            response_data = {
                'user': UserSerializer(user).data,
                'provider': user.provider
            }

            response = JsonResponse({
                'data': response_data,
                'message': success_message
            })

            response.set_cookie(
                key='access',
                value=access_token,
                httponly=True,
                secure=True,
                samesite='None',
                max_age=3600
            )

            response.set_cookie(
                key='refresh',
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite='None',
                max_age=7 * 24 * 3600
            )

            return custom_response(
                data=response_data,
                message=success_message,
                status_code=status.HTTP_200_OK
            )
        else:
            return custom_error_response(
                message=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST
            )

    @extend_schema(
        tags=['Authentication'],
        description="Register a new user account"
    ) 
    @action(detail=False, methods=['post'])
    def register(self, request):
        """
        Register a new user 
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()

                response_data = {
                    'user': UserSerializer(user).data
                }

                return custom_response(
                    data=response_data,
                    message='User registered successfully',
                    status_code=status.HTTP_201_CREATED
                )

            except IntegrityError as e:
                # Log and return detailed integrity error
                print(f"IntegrityError during registration: {str(e)}")
                return custom_error_response(
                    message=f"Integrity error: {str(e)}",   # fixed f-string
                    status_code=status.HTTP_400_BAD_REQUEST
                )

            except Exception as e:
                print(f"Unexpected error during registration: {str(e)}")
                return custom_error_response(
                    message=f"Unexpected error: {str(e)}",  # fixed f-string
                    status_code=status.HTTP_400_BAD_REQUEST
                )

        # If serializer is not valid
        return custom_error_response(
            message=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST   # ✅ fixed typo
        )

    @extend_schema(
        tags=['Authentication'],
        description="Login user and return JWT tokens."
    ) 
    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def login(self, request):
        """Login user and return JWT tokens - validation handled at model level"""
        data = request.data
        
        # Authenticate user with provided credentials
        user = authenticate(
            request=request,
            username=data.get('email_address'),
            password=data.get('password')
        )
        
        if not user:
            return custom_error_response(
                message='Invalid email or password',
                status_code=status.HTTP_401_UNAUTHORIZED
            )
        # Update last login timestamp
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        refresh = RefreshToken.for_user(user)

        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        # Prepare the data you want in the response body
        response_data = {
            'access_token': access_token,
            # 'token_type': 'Bearer',
            # 'expires_in': refresh.access_token.lifetime.total_seconds(),
            'user': UserSerializer(user).data,
        }

        # Use JsonResponse so we can attach cookies
        response = JsonResponse({
            'data': response_data,
            'message': 'Login successful'
        })

        # Set access token cookie (shorter-lived)
        response.set_cookie(
            key='access',
            value=access_token,
            httponly=True,
            secure=False,            
            samesite='Lax',
            max_age=3600  # set to 1 hour
        )

        # Set refresh token cookie (longer-lived)
        response.set_cookie(
            key='refresh',
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=7 * 24 * 3600  # 7 days
        )

        return response
