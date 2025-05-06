from functools import wraps
from django_ratelimit.decorators import ratelimit as django_ratelimit
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

def login_ratelimit(view_func):
    """
    Rate limit decorator specifically for login attempts.
    Limits based on username + IP to prevent username enumeration attacks.
    """
    @wraps(view_func)
    @django_ratelimit(key='post:email', rate=getattr(settings, 'RATELIMIT_LOGIN', '5/m'), 
                    method=['POST'], block=True)
    @django_ratelimit(key='ip', rate=getattr(settings, 'RATELIMIT_LOGIN_IP', '10/m'), 
                    method=['POST'], block=True)
    def wrapped(request, *args, **kwargs):
        return view_func(request, *args, **kwargs)
    return wrapped

def register_ratelimit(view_func):
    """
    Rate limit decorator for registration attempts.
    """
    @wraps(view_func)
    @django_ratelimit(key='ip', rate=getattr(settings, 'RATELIMIT_SIGNUP', '3/h'), 
                    method=['POST'], block=True)
    def wrapped(request, *args, **kwargs):
        return view_func(request, *args, **kwargs)
    return wrapped

def password_reset_ratelimit(view_func):
    """
    Rate limit decorator for password reset attempts.
    """
    @wraps(view_func)
    @django_ratelimit(key='post:email', rate=getattr(settings, 'RATELIMIT_PASSWORD_RESET', '3/h'), 
                    method=['POST'], block=True)
    @django_ratelimit(key='ip', rate=getattr(settings, 'RATELIMIT_PASSWORD_RESET_IP', '5/h'), 
                    method=['POST'], block=True)
    def wrapped(request, *args, **kwargs):
        return view_func(request, *args, **kwargs)
    return wrapped

def ratelimit_handler(func):
    """
    Custom handler for rate limited requests.
    """
    @wraps(func)
    def wrapped(self, request, *args, **kwargs):
        if getattr(request, 'limited', False):
            return Response(
                {"error": "Too many attempts. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        return func(self, request, *args, **kwargs)
    return wrapped