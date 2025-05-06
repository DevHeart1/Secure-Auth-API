import pytest
from django.test import TestCase
from rest_framework.exceptions import ValidationError
from authentication.models import User, VerificationToken
from authentication.serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
)

@pytest.mark.django_db
class TestUserRegistrationSerializer:
    def test_valid_registration_data(self):
        """Test serializer with valid registration data"""
        data = {
            'email': 'newuser@example.com',
            'password': 'SecurePassword123!',
            'password_confirm': 'SecurePassword123!',
            'first_name': 'John',
            'last_name': 'Doe'
        }
        serializer = UserRegistrationSerializer(data=data)
        assert serializer.is_valid()
        user = serializer.save()
        assert user.email == 'newuser@example.com'
        assert user.first_name == 'John'
        assert user.last_name == 'Doe'
        assert user.check_password('SecurePassword123!')
        
    def test_password_mismatch(self):
        """Test serializer with mismatched passwords"""
        data = {
            'email': 'newuser@example.com',
            'password': 'SecurePassword123!',
            'password_confirm': 'DifferentPassword123!',
        }
        serializer = UserRegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert 'password' in serializer.errors
        
    def test_weak_password(self):
        """Test serializer with weak password"""
        data = {
            'email': 'newuser@example.com',
            'password': 'password',
            'password_confirm': 'password',
        }
        serializer = UserRegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert 'password' in serializer.errors
        
    def test_existing_email(self):
        """Test serializer with existing email"""
        # Create a user first
        User.objects.create_user(email='existing@example.com', password='ExistingPass123!')
        
        # Try to register with the same email
        data = {
            'email': 'existing@example.com',
            'password': 'NewPassword123!',
            'password_confirm': 'NewPassword123!',
        }
        serializer = UserRegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert 'email' in serializer.errors

@pytest.mark.django_db
class TestUserProfileSerializer:
    def test_user_profile_serialization(self):
        """Test serializing a user profile"""
        user = User.objects.create_user(
            email='profile@example.com',
            first_name='Jane',
            last_name='Smith',
            password='password123'
        )
        
        serializer = UserProfileSerializer(user)
        data = serializer.data
        
        assert data['email'] == 'profile@example.com'
        assert data['first_name'] == 'Jane'
        assert data['last_name'] == 'Smith'
        assert 'password' not in data
        
    def test_profile_update(self):
        """Test updating a user profile"""
        user = User.objects.create_user(
            email='update@example.com',
            first_name='Original',
            last_name='Name',
            password='password123'
        )
        
        update_data = {
            'first_name': 'Updated',
            'last_name': 'User'
        }
        
        serializer = UserProfileSerializer(user, data=update_data, partial=True)
        assert serializer.is_valid()
        updated_user = serializer.save()
        
        assert updated_user.first_name == 'Updated'
        assert updated_user.last_name == 'User'
        assert updated_user.email == 'update@example.com'  # Email should remain unchanged

@pytest.mark.django_db
class TestPasswordResetConfirmSerializer:
    def test_password_reset_validation(self):
        """Test password reset confirmation serializer validation"""
        data = {
            'token': '123e4567-e89b-12d3-a456-426614174000',
            'new_password': 'NewSecurePass123!',
            'new_password_confirm': 'NewSecurePass123!'
        }
        serializer = PasswordResetConfirmSerializer(data=data)
        assert serializer.is_valid()
        
    def test_password_reset_mismatch(self):
        """Test password reset with mismatched passwords"""
        data = {
            'token': '123e4567-e89b-12d3-a456-426614174000',
            'new_password': 'NewSecurePass123!',
            'new_password_confirm': 'DifferentPass123!'
        }
        serializer = PasswordResetConfirmSerializer(data=data)
        assert not serializer.is_valid()
        assert 'new_password' in serializer.errors