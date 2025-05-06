"""
Custom decorators for authentication views.
"""
import functools
import hashlib
from django.http import HttpResponse
from django.conf import settings
import time
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger('authentication.security')

def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def rate_limit(key_func, rate_limit_count, time_period):
    """
    Custom rate limiter decorator that limits the number of requests 
    a user can make within a time period based on a dynamic key.
    
    Args:
        key_func: Function that returns the rate limiting key (e.g. IP or user ID)
        rate_limit_count: Max number of requests allowed
        time_period: Time period in seconds
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Get the rate limiting key
            cache_key = key_func(request)
            
            # Get current count from cache
            current_count = cache.get(cache_key, 0)
            
            if current_count >= rate_limit_count:
                logger.warning(f"Rate limit exceeded for {cache_key}")
                
                # Check if it's a DRF request or Django request
                if hasattr(request, '_request'):
                    # DRF Request object
                    return Response(
                        {"error": "Rate limit exceeded. Please try again later.", "code": "rate_limit_exceeded"},
                        status=status.HTTP_429_TOO_MANY_REQUESTS
                    )
                else:
                    # Django HttpRequest
                    return HttpResponse(
                        "Rate limit exceeded. Please try again later.",
                        status=429
                    )
            
            # Increment the count
            if current_count == 0:
                # First request in this period
                cache.set(cache_key, 1, time_period)
            else:
                # Increment existing count
                cache.incr(cache_key)
                
            # Process the request
            return view_func(request, *args, **kwargs)
        
        return wrapped_view
    
    return decorator

def login_ratelimit(view_func):
    """Rate limit for login attempts - 5 per minute per IP"""
    @functools.wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        ip = get_client_ip(request)
        
        # Rate limit by IP
        ip_key = f"login_ratelimit_ip_{ip}"
        ip_limit = getattr(settings, 'LOGIN_RATELIMIT_IP', 5)
        ip_period = getattr(settings, 'LOGIN_RATELIMIT_IP_PERIOD', 60)  # 1 minute
        
        # Check if IP is rate limited
        ip_count = cache.get(ip_key, 0)
        if ip_count >= ip_limit:
            logger.warning(f"Login rate limit exceeded for IP: {ip}")
            return Response(
                {"error": "Too many login attempts. Please try again later.", "code": "rate_limit_exceeded"},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        # If email is provided, also rate limit by email
        email = None
        if request.method == 'POST' and hasattr(request, 'data') and 'email' in request.data:
            email = request.data['email']
            email_hash = hashlib.sha256(email.encode()).hexdigest()
            email_key = f"login_ratelimit_email_{email_hash}"
            email_limit = getattr(settings, 'LOGIN_RATELIMIT_EMAIL', 5)
            email_period = getattr(settings, 'LOGIN_RATELIMIT_EMAIL_PERIOD', 300)  # 5 minutes
            
            # Check if email is rate limited
            email_count = cache.get(email_key, 0)
            if email_count >= email_limit:
                logger.warning(f"Login rate limit exceeded for email: {email}")
                # Return the same error to prevent user enumeration
                return Response(
                    {"error": "Too many login attempts. Please try again later.", "code": "rate_limit_exceeded"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            
            # Increment email count
            if email_count == 0:
                cache.set(email_key, 1, email_period)
            else:
                cache.incr(email_key)
        
        # Increment IP count
        if ip_count == 0:
            cache.set(ip_key, 1, ip_period)
        else:
            cache.incr(ip_key)
        
        # Process the request
        return view_func(request, *args, **kwargs)
    
    return wrapped_view

def register_ratelimit(view_func):
    """Rate limit for registration - 3 per hour per IP"""
    key_func = lambda request: f"register_ratelimit_{get_client_ip(request)}"
    return rate_limit(key_func, 
                     getattr(settings, 'REGISTER_RATELIMIT', 3),
                     getattr(settings, 'REGISTER_RATELIMIT_PERIOD', 3600))(view_func)

def password_reset_ratelimit(view_func):
    """Rate limit for password reset requests - 3 per hour per IP"""
    @functools.wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        ip = get_client_ip(request)
        
        # Rate limit by IP
        ip_key = f"password_reset_ratelimit_ip_{ip}"
        ip_limit = getattr(settings, 'PASSWORD_RESET_RATELIMIT_IP', 3)
        ip_period = getattr(settings, 'PASSWORD_RESET_RATELIMIT_IP_PERIOD', 3600)  # 1 hour
        
        # Check if IP is rate limited
        ip_count = cache.get(ip_key, 0)
        if ip_count >= ip_limit:
            logger.warning(f"Password reset rate limit exceeded for IP: {ip}")
            return Response(
                {"error": "Too many password reset attempts. Please try again later.", "code": "rate_limit_exceeded"},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        # If email is provided, also rate limit by email
        email = None
        if request.method == 'POST' and hasattr(request, 'data') and 'email' in request.data:
            email = request.data['email']
            email_hash = hashlib.sha256(email.encode()).hexdigest()
            email_key = f"password_reset_ratelimit_email_{email_hash}"
            email_limit = getattr(settings, 'PASSWORD_RESET_RATELIMIT_EMAIL', 3)
            email_period = getattr(settings, 'PASSWORD_RESET_RATELIMIT_EMAIL_PERIOD', 86400)  # 24 hours
            
            # Check if email is rate limited
            email_count = cache.get(email_key, 0)
            if email_count >= email_limit:
                logger.warning(f"Password reset rate limit exceeded for email: {email}")
                # Still return success to prevent user enumeration
                return Response(
                    {"message": "If your email is registered, you will receive password reset instructions."},
                    status=status.HTTP_200_OK
                )
            
            # Increment email count
            if email_count == 0:
                cache.set(email_key, 1, email_period)
            else:
                cache.incr(email_key)
        
        # Increment IP count
        if ip_count == 0:
            cache.set(ip_key, 1, ip_period)
        else:
            cache.incr(ip_key)
        
        # Process the request
        return view_func(request, *args, **kwargs)
    
    return wrapped_view

def api_key_ratelimit(view_func):
    """Rate limit for API key generation - 3 per day per user"""
    @functools.wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if request.user and request.user.is_authenticated:
            key = f"api_key_ratelimit_user_{request.user.id}"
            limit = getattr(settings, 'API_KEY_RATELIMIT', 3)
            period = getattr(settings, 'API_KEY_RATELIMIT_PERIOD', 86400)  # 24 hours
            
            # Check if user is rate limited
            count = cache.get(key, 0)
            if count >= limit:
                logger.warning(f"API key generation rate limit exceeded for user: {request.user.id}")
                return Response(
                    {"error": "API key generation limit exceeded. Please try again tomorrow.", "code": "rate_limit_exceeded"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            
            # Increment count
            if count == 0:
                cache.set(key, 1, period)
            else:
                cache.incr(key)
        
        # Process the request
        return view_func(request, *args, **kwargs)
    
    return wrapped_view

def ratelimit_handler(view_func):
    """Handler for rate limited requests that returns a proper API response"""
    @functools.wraps(view_func)
    def wrapped_view(self, request, *args, **kwargs):
        try:
            return view_func(self, request, *args, **kwargs)
        except Exception as e:
            if hasattr(e, 'status_code') and e.status_code == 429:
                # Log the rate limit violation
                log_data = {
                    'path': request.path,
                    'method': request.method,
                    'user': request.user.email if request.user.is_authenticated else 'anonymous',
                    'ip': get_client_ip(request),
                }
                logger.warning(f"Rate limit exceeded: {log_data}")
                
                return Response(
                    {"error": "Rate limit exceeded. Please try again later.", "code": "rate_limit_exceeded"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            raise
    return wrapped_view

def sensitive_post_parameters(*parameters):
    """
    Decorator that marks parameters as sensitive in logs and error reports.
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Process the request
            return view_func(request, *args, **kwargs)
        
        # Mark the view as having sensitive parameters
        wrapped_view.sensitive_post_parameters = parameters
        return wrapped_view
    
    return decorator
