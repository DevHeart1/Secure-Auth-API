import pytest
import json
import uuid
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from rest_framework import status
from rest_framework.test import APIClient
from authentication.models import User, VerificationToken

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def test_user():
    user = User.objects.create_user(
        email='test@example.com',
        password='TestPassword123!',
        first_name='Test',
        last_name='User'
    )
    user.is_verified = True
    user.save()
    return user

@pytest.fixture
def verified_token(test_user):
    return VerificationToken.objects.create(
        user=test_user,
        token_type='EMAIL_VERIFY',
        expires_at=timezone.now() + timedelta(hours=24)
    )

@pytest.fixture
def reset_token(test_user):
    return VerificationToken.objects.create(
        user=test_user,
        token_type='PASSWORD_RESET',
        expires_at=timezone.now() + timedelta(hours=1)
    )

@pytest.mark.django_db
class TestRegistrationViews:
    def test_successful_registration(self, api_client):
        """Test successful user registration"""
        url = reverse('auth-register')
        data = {
            'email': 'newuser@example.com',
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!',
            'first_name': 'New',
            'last_name': 'User'
        }
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_201_CREATED
        assert 'message' in response.data
        assert User.objects.filter(email='newuser@example.com').exists()
        new_user = User.objects.get(email='newuser@example.com')
        assert not new_user.is_verified
        
        # Check that a verification token was created
        assert VerificationToken.objects.filter(user=new_user, token_type='EMAIL_VERIFY').exists()

    def test_invalid_registration_data(self, api_client):
        """Test registration with invalid data"""
        url = reverse('auth-register')
        # Missing required field (password_confirm)
        data = {
            'email': 'invalid@example.com',
            'password': 'SecurePass123!',
        }
        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

@pytest.mark.django_db
class TestLoginViews:
    def test_successful_login(self, api_client, test_user):
        """Test successful user login"""
        url = reverse('auth-login')
        data = {
            'email': 'test@example.com',
            'password': 'TestPassword123!',
        }
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data

    def test_invalid_credentials(self, api_client):
        """Test login with invalid credentials"""
        url = reverse('auth-login')
        data = {
            'email': 'nonexistent@example.com',
            'password': 'WrongPassword123!',
        }
        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_unverified_user_login(self, api_client):
        """Test login attempt from an unverified user"""
        # Create unverified user
        unverified_user = User.objects.create_user(
            email='unverified@example.com',
            password='Password123!'
        )
        
        url = reverse('auth-login')
        data = {
            'email': 'unverified@example.com',
            'password': 'Password123!',
        }
        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.django_db
class TestEmailVerificationViews:
    def test_successful_verification(self, api_client, test_user):
        """Test successful email verification"""
        # Create a non-verified user for this test
        user = User.objects.create_user(email='verify@example.com', password='Password123!')
        token = VerificationToken.objects.create(
            user=user,
            token_type='EMAIL_VERIFY',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        url = reverse('auth-verify-email')
        data = {
            'token': str(token.token),
        }
        
        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_200_OK
        
        # Refresh user from database and verify status
        user.refresh_from_db()
        assert user.is_verified is True
        
        # Check token was marked as used
        token.refresh_from_db()
        assert token.is_used is True

    def test_invalid_token_verification(self, api_client):
        """Test email verification with invalid token"""
        url = reverse('auth-verify-email')
        data = {
            'token': str(uuid.uuid4()),  # Random token that doesn't exist
        }
        
        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

@pytest.mark.django_db
class TestPasswordResetViews:
    def test_password_reset_request(self, api_client, test_user):
        """Test password reset request"""
        url = reverse('auth-password-reset-request')
        data = {
            'email': test_user.email,
        }
        
        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_200_OK
        
        # Verify a token was created
        assert VerificationToken.objects.filter(
            user=test_user, 
            token_type='PASSWORD_RESET', 
            is_used=False
        ).exists()

    def test_password_reset_confirm(self, api_client, reset_token):
        """Test password reset confirmation"""
        url = reverse('auth-password-reset-confirm')
        data = {
            'token': str(reset_token.token),
            'new_password': 'NewSecurePass123!',
            'new_password_confirm': 'NewSecurePass123!'
        }
        
        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_200_OK
        
        # Verify token was marked as used
        reset_token.refresh_from_db()
        assert reset_token.is_used is True
        
        # Verify password was changed
        user = reset_token.user
        user.refresh_from_db()
        assert user.check_password('NewSecurePass123!')

@pytest.mark.django_db
class TestProfileViews:
    def test_get_profile(self, api_client, test_user):
        """Test getting user profile"""
        url = reverse('auth-profile')
        api_client.force_authenticate(user=test_user)
        
        response = api_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == test_user.email
        assert response.data['first_name'] == test_user.first_name
        assert response.data['last_name'] == test_user.last_name

    def test_update_profile(self, api_client, test_user):
        """Test updating user profile"""
        url = reverse('auth-profile')
        api_client.force_authenticate(user=test_user)
        
        data = {
            'first_name': 'Updated',
            'last_name': 'Name'
        }
        
        response = api_client.patch(url, data, format='json')
        assert response.status_code == status.HTTP_200_OK
        
        # Verify profile was updated
        test_user.refresh_from_db()
        assert test_user.first_name == 'Updated'
        assert test_user.last_name == 'Name'

    def test_unauthorized_profile_access(self, api_client):
        """Test profile access without authentication"""
        url = reverse('auth-profile')
        response = api_client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED