import logging
import json
from django.utils import timezone

# Configure logger
logger = logging.getLogger('authentication.security')

class SecurityLoggingMiddleware:
    """
    Middleware to log authentication and security-related events
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Log authentication attempts and security-related events
        if request.path.startswith('/api/v1/auth/'):
            self._log_auth_event(request, response)

        return response

    def _log_auth_event(self, request, response):
        """Log authentication events"""
        event_data = {
            'timestamp': timezone.now().isoformat(),
            'ip_address': self._get_client_ip(request),
            'path': request.path,
            'method': request.method,
            'status_code': response.status_code,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        }

        # Add username for login attempts (without logging the password)
        if request.path.endswith('/login/') and request.method == 'POST':
            try:
                body_data = json.loads(request.body.decode('utf-8'))
                if 'email' in body_data:
                    event_data['email'] = body_data['email']
                    event_data['event_type'] = 'login_attempt'
                    if response.status_code == 200:
                        event_data['result'] = 'success'
                    else:
                        event_data['result'] = 'failure'
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        # For password reset attempts
        elif 'password_reset' in request.path and request.method == 'POST':
            event_data['event_type'] = 'password_reset_request'

        # For registration attempts
        elif request.path.endswith('/register/') and request.method == 'POST':
            event_data['event_type'] = 'registration'
            if response.status_code == 201:  # Created
                try:
                    body_data = json.loads(request.body.decode('utf-8'))
                    if 'email' in body_data:
                        event_data['email'] = body_data['email']
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        # Log with appropriate level based on status code
        if response.status_code >= 400:
            logger.warning(json.dumps(event_data))
        else:
            logger.info(json.dumps(event_data))

    def _get_client_ip(self, request):
        """Get client IP address from request headers"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip