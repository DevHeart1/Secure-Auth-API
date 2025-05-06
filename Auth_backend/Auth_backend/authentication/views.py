from django.shortcuts import render
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django_ratelimit.decorators import ratelimit
from functools import wraps
import uuid
import jwt
from .models import User, VerificationToken
from .tasks import send_verification_email, send_password_reset_email
from .oauth2 import GoogleOAuth2Provider, GitHubOAuth2Provider
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer,
    TokenRefreshSerializer,
    GoogleAuthSerializer,
    GitHubAuthSerializer
)
from .decorators import login_ratelimit, register_ratelimit, password_reset_ratelimit, ratelimit_handler

class AuthViewSet(viewsets.ViewSet):
    """
    API endpoint for user authentication and management
    """
    permission_classes = [AllowAny]

    @action(detail=False, methods=['post'])
    @register_ratelimit
    @ratelimit_handler
    def register(self, request):
        """
        Register a new user with email/password
        """
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Create verification token
            token = VerificationToken.objects.create(
                user=user,
                token_type='EMAIL_VERIFY',
                expires_at=timezone.now() + timedelta(hours=24)
            )
            
            # Generate verification URL
            verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token.token}"
            
            # Send verification email asynchronously
            send_verification_email.delay(user.email, verification_url)
            
            return Response(
                {"message": "User registered successfully. Please check your email for verification."},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @login_ratelimit
    @ratelimit_handler
    def login(self, request):
        """
        Login with email/password and return JWT tokens
        """
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            
            user = authenticate(email=email, password=password)
            
            if user is None:
                return Response(
                    {"error": "Invalid email or password"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
                
            if not user.is_verified:
                return Response(
                    {"error": "Email not verified. Please check your inbox for verification email."},
                    status=status.HTTP_403_FORBIDDEN
                )
                
            if not user.is_active:
                return Response(
                    {"error": "Account is disabled."},
                    status=status.HTTP_403_FORBIDDEN
                )
                
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def verify_email(self, request):
        """
        Verify user email with token
        """
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            token_str = serializer.validated_data['token']
            
            try:
                token = VerificationToken.objects.get(
                    token=token_str,
                    token_type='EMAIL_VERIFY',
                    is_used=False,
                    expires_at__gt=timezone.now()
                )
                
                user = token.user
                user.is_verified = True
                user.save()
                
                token.is_used = True
                token.save()
                
                return Response(
                    {"message": "Email verified successfully. You can now login."},
                    status=status.HTTP_200_OK
                )
                
            except VerificationToken.DoesNotExist:
                return Response(
                    {"error": "Invalid or expired verification token."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @password_reset_ratelimit
    @ratelimit_handler
    def password_reset_request(self, request):
        """
        Request password reset email
        """
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = User.objects.get(email=email)
                
                # Create password reset token
                token = VerificationToken.objects.create(
                    user=user,
                    token_type='PASSWORD_RESET',
                    expires_at=timezone.now() + timedelta(hours=1)
                )
                
                # Generate reset URL
                reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token.token}"
                
                # Send password reset email asynchronously
                send_password_reset_email.delay(user.email, reset_url)
                
                return Response(
                    {"message": "Password reset email sent. Please check your inbox."},
                    status=status.HTTP_200_OK
                )
                
            except User.DoesNotExist:
                # Return success even if user doesn't exist to prevent user enumeration
                return Response(
                    {"message": "If your email is registered, you will receive password reset instructions."},
                    status=status.HTTP_200_OK
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def password_reset_confirm(self, request):
        """
        Confirm password reset with token and new password
        """
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token_str = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            
            try:
                token = VerificationToken.objects.get(
                    token=token_str,
                    token_type='PASSWORD_RESET',
                    is_used=False,
                    expires_at__gt=timezone.now()
                )
                
                user = token.user
                user.set_password(new_password)
                user.save()
                
                token.is_used = True
                token.save()
                
                return Response(
                    {"message": "Password reset successful. You can now login with your new password."},
                    status=status.HTTP_200_OK
                )
                
            except VerificationToken.DoesNotExist:
                return Response(
                    {"error": "Invalid or expired password reset token."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def refresh_token(self, request):
        """
        Refresh JWT tokens
        """
        serializer = TokenRefreshSerializer(data=request.data)
        if serializer.is_valid():
            try:
                refresh = RefreshToken(serializer.validated_data['refresh'])
                
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                })
                
            except Exception as e:
                return Response(
                    {"error": "Invalid refresh token."},
                    status=status.HTTP_401_UNAUTHORIZED
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get', 'patch'], permission_classes=[IsAuthenticated])
    def profile(self, request):
        """
        Get or update user profile
        """
        user = request.user
        
        if request.method == 'PATCH':
            serializer = UserProfileSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def google_auth(self, request):
        """
        Login or register with Google OAuth
        """
        serializer = GoogleAuthSerializer(data=request.data)
        if serializer.is_valid():
            id_token = serializer.validated_data['id_token']
            
            try:
                google_provider = GoogleOAuth2Provider()
                user_info = google_provider.get_user_info(id_token)
                
                # Check if user exists
                try:
                    user = User.objects.get(email=user_info['email'])
                except User.DoesNotExist:
                    # Create new user
                    user = User.objects.create_user(
                        email=user_info['email'],
                        first_name=user_info['first_name'],
                        last_name=user_info['last_name'],
                        password=None,  # Set unusable password
                        is_verified=user_info['is_verified']
                    )
                
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'is_new_user': user.date_joined > (timezone.now() - timedelta(seconds=5))
                })
                
            except Exception as e:
                return Response(
                    {"error": str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def github_auth(self, request):
        """
        Login or register with GitHub OAuth
        """
        serializer = GitHubAuthSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            state = serializer.validated_data['state']
            
            try:
                github_provider = GitHubOAuth2Provider()
                
                # Exchange code for token
                access_token = github_provider.exchange_code_for_token(code)
                
                # Get user info
                user_info = github_provider.get_user_info(access_token)
                
                # Check if user exists
                try:
                    user = User.objects.get(email=user_info['email'])
                except User.DoesNotExist:
                    # Create new user
                    user = User.objects.create_user(
                        email=user_info['email'],
                        first_name=user_info['first_name'],
                        last_name=user_info['last_name'],
                        password=None,  # Set unusable password
                        is_verified=user_info['is_verified']
                    )
                
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'is_new_user': user.date_joined > (timezone.now() - timedelta(seconds=5))
                })
                
            except Exception as e:
                return Response(
                    {"error": str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
