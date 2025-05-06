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

def ratelimit_handler(func):
    @wraps(func)
    def wrapped(self, request, *args, **kwargs):
        if getattr(request, 'limited', False):
            return Response(
                {"error": "Too many attempts. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        return func(self, request, *args, **kwargs)
    return wrapped

class AuthViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    
    def get_serializer_class(self):
        if self.action == 'google_auth':
            return GoogleAuthSerializer
        elif self.action == 'github_auth':
            return GitHubAuthSerializer
        elif self.action == 'register':
            return UserRegistrationSerializer
        elif self.action == 'login':
            return UserLoginSerializer
        elif self.action == 'profile':
            return UserProfileSerializer
        elif self.action == 'password_reset_request':
            return PasswordResetRequestSerializer
        elif self.action == 'password_reset_confirm':
            return PasswordResetConfirmSerializer
        elif self.action == 'verify_email':
            return EmailVerificationSerializer
        return TokenRefreshSerializer

    def _create_or_update_user_from_oauth(self, user_info, provider_id_field):
        email = user_info['email']
        try:
            user = User.objects.get(email=email)
            # Update existing user with OAuth provider ID if not set
            if not getattr(user, provider_id_field):
                setattr(user, provider_id_field, user_info[provider_id_field])
                user.save()
        except User.DoesNotExist:
            # Create new user
            user = User.objects.create_user(
                email=email,
                first_name=user_info['first_name'],
                last_name=user_info['last_name'],
                is_verified=user_info['is_verified']
            )
            setattr(user, provider_id_field, user_info[provider_id_field])
            user.save()
        
        return user

    @action(detail=False, methods=['post'])
    @ratelimit(key='ip', rate='5/m', method=['POST'])
    @ratelimit_handler
    def register(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Create verification token
            token = VerificationToken.objects.create(
                user=user,
                token_type='EMAIL_VERIFY',
                expires_at=timezone.now() + timedelta(hours=24)
            )
            # Send verification email asynchronously
            verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token.token}"
            send_verification_email.delay(user.email, verification_url)
            
            return Response(
                {"message": "Registration successful. Please check your email to verify your account."},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @ratelimit(key='ip', rate='5/m', method=['POST'])
    @ratelimit_handler
    def login(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                email=serializer.validated_data['email'],
                password=serializer.validated_data['password']
            )
            if user and user.is_active:
                if not user.is_verified:
                    return Response(
                        {"error": "Please verify your email before logging in."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                refresh = RefreshToken.for_user(user)
                user.last_login = timezone.now()
                user.save()
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                })
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get', 'patch'], permission_classes=[IsAuthenticated])
    def profile(self, request):
        if request.method == 'GET':
            serializer = self.get_serializer(request.user)
            return Response(serializer.data)
        elif request.method == 'PATCH':
            serializer = self.get_serializer(request.user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @ratelimit(key='ip', rate='3/h', method=['POST'])
    @ratelimit_handler
    def password_reset_request(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(email=serializer.validated_data['email'])
                if user.is_active:
                    token = VerificationToken.objects.create(
                        user=user,
                        token_type='PASSWORD_RESET',
                        expires_at=timezone.now() + timedelta(hours=1)
                    )
                    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token.token}"
                    # Send password reset email asynchronously
                    send_password_reset_email.delay(user.email, reset_url)
            except User.DoesNotExist:
                pass
            return Response({"message": "If an account exists with this email, a password reset link has been sent."})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @ratelimit(key='ip', rate='5/m', method=['POST'])
    @ratelimit_handler
    def password_reset_confirm(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                token_obj = VerificationToken.objects.get(
                    token=serializer.validated_data['token'],
                    token_type='PASSWORD_RESET',
                    is_used=False,
                    expires_at__gt=timezone.now()
                )
                user = token_obj.user
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                token_obj.is_used = True
                token_obj.save()
                # Invalidate all refresh tokens
                RefreshToken.for_user(user)
                return Response({"message": "Password has been reset successfully."})
            except VerificationToken.DoesNotExist:
                return Response(
                    {"error": "Invalid or expired token"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def verify_email(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                token_obj = VerificationToken.objects.get(
                    token=serializer.validated_data['token'],
                    token_type='EMAIL_VERIFY',
                    is_used=False,
                    expires_at__gt=timezone.now()
                )
                user = token_obj.user
                user.is_verified = True
                user.save()
                token_obj.is_used = True
                token_obj.save()
                return Response({"message": "Email verified successfully."})
            except VerificationToken.DoesNotExist:
                return Response(
                    {"error": "Invalid or expired token"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @ratelimit(key='ip', rate='5/m', method=['POST'])
    @ratelimit_handler
    def token_refresh(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                refresh = RefreshToken(serializer.validated_data['refresh'])
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)  # New refresh token if rotation is enabled
                })
            except Exception:
                return Response(
                    {"error": "Invalid or expired refresh token"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @ratelimit(key='ip', rate='5/m', method=['POST'])
    @ratelimit_handler
    def google_auth(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                provider = GoogleOAuth2Provider()
                user_info = provider.get_user_info(serializer.validated_data['id_token'])
                
                user = self._create_or_update_user_from_oauth(user_info, 'google_id')
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                })
            except Exception as e:
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @ratelimit(key='ip', rate='5/m', method=['POST'])
    @ratelimit_handler
    def github_auth(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                provider = GitHubOAuth2Provider()
                # Exchange the code for an access token
                access_token = provider.exchange_code_for_token(
                    serializer.validated_data['code']
                )
                # Get user information using the access token
                user_info = provider.get_user_info(access_token)
                
                user = self._create_or_update_user_from_oauth(user_info, 'github_id')
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                })
            except Exception as e:
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
