from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
from django.core.exceptions import ValidationError
import requests as http_requests

class OAuth2Provider:
    def verify_token(self, token):
        raise NotImplementedError("Subclasses must implement verify_token")

    def get_user_info(self, token):
        raise NotImplementedError("Subclasses must implement get_user_info")

class GoogleOAuth2Provider(OAuth2Provider):
    def verify_token(self, token):
        try:
            idinfo = id_token.verify_oauth2_token(
                token,
                requests.Request(),
                settings.GOOGLE_OAUTH2_CLIENT_ID
            )
            
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValidationError('Wrong issuer.')
                
            return idinfo
            
        except Exception as e:
            raise ValidationError(f"Token verification failed: {str(e)}")

    def get_user_info(self, token):
        try:
            idinfo = self.verify_token(token)
            return {
                'email': idinfo['email'],
                'first_name': idinfo.get('given_name', ''),
                'last_name': idinfo.get('family_name', ''),
                'google_id': idinfo['sub'],
                'is_verified': idinfo['email_verified']
            }
        except Exception as e:
            raise ValidationError(f"Failed to get user info: {str(e)}")

class GitHubOAuth2Provider(OAuth2Provider):
    def exchange_code_for_token(self, code):
        response = http_requests.post(
            'https://github.com/login/oauth/access_token',
            headers={
                'Accept': 'application/json'
            },
            data={
                'client_id': settings.GITHUB_OAUTH2_CLIENT_ID,
                'client_secret': settings.GITHUB_OAUTH2_CLIENT_SECRET,
                'code': code
            }
        )
        if response.status_code != 200:
            raise ValidationError("Failed to exchange code for token")
        
        return response.json().get('access_token')

    def get_user_info(self, access_token):
        headers = {
            'Authorization': f'token {access_token}',
            'Accept': 'application/json'
        }
        
        # Get user profile
        user_response = http_requests.get(
            'https://api.github.com/user',
            headers=headers
        )
        if user_response.status_code != 200:
            raise ValidationError("Failed to get GitHub user info")
        
        user_data = user_response.json()
        
        # Get user emails
        email_response = http_requests.get(
            'https://api.github.com/user/emails',
            headers=headers
        )
        if email_response.status_code != 200:
            raise ValidationError("Failed to get GitHub email info")
        
        # Find primary email
        primary_email = next(
            (email for email in email_response.json() 
             if email['primary'] and email['verified']),
            None
        )
        
        if not primary_email:
            raise ValidationError("No verified primary email found")
        
        name_parts = (user_data.get('name') or '').split(' ', 1)
        first_name = name_parts[0] if name_parts else ''
        last_name = name_parts[1] if len(name_parts) > 1 else ''
        
        return {
            'email': primary_email['email'],
            'first_name': first_name,
            'last_name': last_name,
            'github_id': str(user_data['id']),
            'is_verified': True  # GitHub emails are verified by GitHub
        }