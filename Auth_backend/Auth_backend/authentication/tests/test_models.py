import pytest
from django.utils import timezone
from datetime import timedelta
from django.test import TestCase
from authentication.models import User, VerificationToken

@pytest.mark.django_db
class TestUserModel:
    def test_create_user(self):
        """Test creating a normal user"""
        user = User.objects.create_user(email="user@example.com", password="strongPass123!")
        assert user.email == "user@example.com"
        assert user.is_active is True
        assert user.is_staff is False
        assert user.is_superuser is False
        assert user.is_verified is False
        assert user.check_password("strongPass123!")

    def test_create_superuser(self):
        """Test creating a superuser"""
        admin = User.objects.create_superuser(email="admin@example.com", password="adminPass123!")
        assert admin.email == "admin@example.com"
        assert admin.is_active is True
        assert admin.is_staff is True
        assert admin.is_superuser is True
        assert admin.is_verified is True
        assert admin.check_password("adminPass123!")

    def test_user_str_representation(self):
        """Test the string representation of a user"""
        user = User.objects.create_user(
            email="test@example.com", 
            first_name="John", 
            last_name="Doe"
        )
        assert str(user.email) == "test@example.com"
        
    def test_get_full_name(self):
        """Test the get_full_name method"""
        user = User.objects.create_user(
            email="test@example.com", 
            first_name="John", 
            last_name="Doe"
        )
        assert user.get_full_name() == "John Doe"
        
    def test_get_short_name(self):
        """Test the get_short_name method"""
        user = User.objects.create_user(
            email="test@example.com", 
            first_name="John", 
            last_name="Doe"
        )
        assert user.get_short_name() == "John"

@pytest.mark.django_db
class TestVerificationTokenModel:
    def test_verification_token_creation(self):
        """Test creating a verification token"""
        user = User.objects.create_user(email="token@example.com", password="password123")
        token = VerificationToken.objects.create(
            user=user,
            token_type='EMAIL_VERIFY',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        assert token.user == user
        assert token.token_type == 'EMAIL_VERIFY'
        assert token.is_used is False
        assert token.expires_at > timezone.now()

    def test_token_expiration(self):
        """Test token expiration logic"""
        user = User.objects.create_user(email="expired@example.com", password="password123")
        # Create expired token
        expired_token = VerificationToken.objects.create(
            user=user,
            token_type='PASSWORD_RESET',
            expires_at=timezone.now() - timedelta(hours=1)
        )
        # Create valid token
        valid_token = VerificationToken.objects.create(
            user=user,
            token_type='PASSWORD_RESET',
            expires_at=timezone.now() + timedelta(hours=1)
        )
        
        assert expired_token.expires_at < timezone.now()
        assert valid_token.expires_at > timezone.now()