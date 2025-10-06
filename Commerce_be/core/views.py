from urllib import response
from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from drf_spectacular.utils import extend_schema, extend_schema_view

from core.serializer import AccountVerificationSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer, SocialRegistrationSerializer, UserLoginSerializer, UserRegistrationSerializer, UserSerializer
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
    description="Register a new user account a."
    ) 
    @action(detail=False, methods=['post'])
    def register(self, request):
        """
        Register a new user and send verification email
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                response_data = {
                    'user': UserSerializer(user).data,
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
                    message=f"Integrity error: {str(e)}",
                    status_code=status.HTTP_400_BAD_REQUEST
                )
            except Exception as e:
                print(f"Unexpected error during registration: {str(e)}")
                return custom_error_response(
                    message="Unexpected error: " + str(e),
                    status_code=status.HTTP_400_BAD_REQUEST
                )

        return custom_error_response(
            message=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST
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
        
        # Use model-level validation for login requirements
        try:
            user.validate_for_login()
        except ValidationError as e:
            return custom_error_response(
                message=str(e),
                status_code=status.HTTP_403_FORBIDDEN
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
            max_age=3600  #set to 1 hour          

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

    @extend_schema(
    tags=['Password Management'],
    description="Request password reset email."
    ) 
    @method_decorator(ratelimit(key='ip', rate='1/30m', block=True))                  # max 1 request per IP in 30 minutes
    @method_decorator(ratelimit(key='post:email_address', rate='1/30m', block=True))  # max 1 reset per email in 30 minutes
    @action(detail=False, methods=['post'], url_path='forgot-password')
    def forgot_password(self, request):
        """Request password reset - always returns success for security"""
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user = User.objects.get(email_address=serializer.validated_data['email_address'])
            if user.is_active:  # Only send if account is active
                reset_token = user.generate_password_reset_token()
                send_password_reset_email(user.email_address, user.full_name, reset_token)
        except (User.DoesNotExist, ValidationError):
            pass  # Don't reveal if email exists or if rate limited
        
        # Always return success message for security
        return Response({
            'status': True,
            'message': 'If an account exists, reset instructions have been sent',
            'data': None
        }, status=status.HTTP_200_OK)

    @extend_schema(
        tags=['Password Management'],
        description="Reset password using reset token."
    ) 
    @action(detail=False, methods=['post'], url_path='reset-password')
    def reset_password(self, request):
        """Reset password using token"""
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user = User.objects.get(password_reset_token=serializer.validated_data['token'])
            is_valid, message = user.verify_password_reset_token(serializer.validated_data['token'])
            
            if is_valid:
                user.reset_password(serializer.validated_data['new_password'])
                return Response({
                    'status': True,
                    'message': 'Password reset successfully',
                    'data': {
                        'email': user.email_address,
                        'reset_at': timezone.now().isoformat()
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'status': False,
                    'message': message,
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except User.DoesNotExist:
            return Response({
                'status': False,
                'message': 'Invalid or expired reset token',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)
 
    @extend_schema(
        tags=['Account Verification'],
        description="Verify user account with email address and verification code."
    ) 
    @action(detail=False, methods=['post'], url_path='verify-account')
    def verify(self, request):
        """
        Verify user account with email address and verification code
        """
        serializer = AccountVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email_address = serializer.validated_data['email_address']
            code = serializer.validated_data['verification_code']
            
            try:
                user = User.objects.get(email_address=email_address)
                
                if user.verify_code(code):
                    refresh = RefreshToken.for_user(user)
                    access_token = str(refresh.access_token)
                    refresh_token = str(refresh)

                    response_data = {
                        'user': UserSerializer(user).data
                    }

                    response = JsonResponse({
                        'data': response_data,
                        # 'token_type': 'Bearer',
                        'message': 'Account verified successfully'
                    })

                    # Set access token in HttpOnly cookie
                    response.set_cookie(
                        key='access',
                        value=access_token,
                        httponly=True,
                        secure=True,
                        samesite='None',  # Use 'None' for cross-site requests
                        max_age=3600          
                    )

                    # Set refresh token in HttpOnly cookie
                    response.set_cookie(
                        key='refresh',
                        value=refresh_token,
                        httponly=True,
                        secure=True,
                        samesite='None',
                        max_age=7 * 24 * 3600
                    )

                    return response

                
                else:
                    return custom_error_response(
                        message='Invalid or expired verification code',
                        status_code=status.HTTP_400_BAD_REQUEST
                    )
                
            except User.DoesNotExist:
                return custom_error_response(
                    message='Invalid or expired verification code',
                    status_code=status.HTTP_404_NOT_FOUND
                )
    
        return custom_error_response(
            message='Invalid verification data',
            data=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    
    @extend_schema(
        tags=['Account Verification'],
        description="Resend verification code to user's email."
    ) 
    @action(detail=False, methods=['post'], url_path='resend-verification-code')
    def resend_verification(self, request):
        """
        Resend verification code using email address
        """
        email_address = request.data.get('email_address')
        
        if not email_address:
            return custom_error_response(
                message='Email address is required',
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(email_address=email_address)
        
            if user.is_verified:
                return custom_error_response(
                    message='Account is already verified',
                    status_code=status.HTTP_400_BAD_REQUEST
                )
        
            # Generate new verification code
            user.generate_verification_code()
        
            # Send verification email
            email_sent = send_verification_email(
                to_email=user.email_address,
                name=user.full_name,
                verification_code=user.verification_code
            )
        
            if email_sent:
                return custom_response(
                    message='Verification code sent successfully to your email'
                )
            else:
                return custom_error_response(
                    message='Failed to send verification email. Please try again later.',
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
        except User.DoesNotExist:
            # Don't reveal if email exists or not for security
            return custom_response(
                message='Verification code sent successfully to your email'
            )
    
    @extend_schema(
        tags=['User Profile'],
        description="Get current user profile information."
    ) 
    @action(detail=False, methods=['get'])
    def profile(self, request):
        """
        Get current user profile
        """
        serializer = UserSerializer(request.user)
        return custom_response(
            data=serializer.data,
            message='Profile retrieved successfully'
        )

    @extend_schema(
        tags=['User Profile'],
        description="Update current user profile information."
    ) 
    @action(detail=False, methods=['put', 'patch'], url_path='profile')
    def update_profile(self, request):
        """
        Update current user profile
        """
        serializer = UserSerializer(
            request.user, 
            data=request.data, 
            partial=request.method == 'PATCH'
        )
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            return custom_response(
                data={'user': serializer.data},
                message='Profile updated successfully'
            )
        return custom_error_response(
            message='Profile update failed',
            status_code=status.HTTP_400_BAD_REQUEST
        )

    @extend_schema(
        tags=['User Management'],
        description="Delete a user account (Admin only)."
    )
    def destroy(self, request, *args, **kwargs):
        """
        Delete a user account (Admin only)
        """
        instance = self.get_object()
        user_info = {
            'id': str(instance.id),
            'email': instance.email_address,
            'name': instance.full_name
        }
        
        # Perform the deletion
        self.perform_destroy(instance)
        
        return custom_response(
            data={'deleted_user': user_info},
            message='User account deleted successfully',
            status_code=status.HTTP_200_OK
        )
