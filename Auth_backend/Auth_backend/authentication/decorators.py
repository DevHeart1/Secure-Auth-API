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

def rate_limit(key_prefix, limit=5, period=60, scope='ip'):
    """
    Rate limiting decorator that can be applied to views or methods.
    
    Args:
        key_prefix (str): Prefix for the rate limit key (e.g., 'login', 'register')
        limit (int): Maximum number of requests allowed in the period
        period (int): Time period in seconds
        scope (str): Scope of the rate limit ('ip', 'user', 'global')
    
    Usage:
        @rate_limit('login', limit=5, period=60)
        def login_view(request):
            ...
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Generate the cache key based on scope
            if scope == 'ip':
                # Use IP address for rate limiting
                client_ip = _get_client_ip(request)
                key = f"ratelimit:{key_prefix}:{client_ip}"
            elif scope == 'user' and hasattr(request, 'user') and request.user.is_authenticated:
                # Use user ID for rate limiting
                key = f"ratelimit:{key_prefix}:user_{request.user.id}"
            elif scope == 'user_or_ip':
                # Use user ID if authenticated, otherwise IP
                if hasattr(request, 'user') and request.user.is_authenticated:
                    key = f"ratelimit:{key_prefix}:user_{request.user.id}"
                else:
                    client_ip = _get_client_ip(request)
                    key = f"ratelimit:{key_prefix}:{client_ip}"
            elif scope == 'param' and 'param_name' in kwargs:
                # Use a specific request parameter
                param_value = kwargs.get('param_name')
                key = f"ratelimit:{key_prefix}:{param_value}"
            else:
                # Global rate limit
                key = f"ratelimit:{key_prefix}:global"
            
            # Get the current count and timestamp from cache
            cache_data = cache.get(key, {'count': 0, 'reset': time.time() + period})
            
            # Check if the period has expired and reset if needed
            if time.time() > cache_data['reset']:
                cache_data = {'count': 0, 'reset': time.time() + period}
            
            # Increment the count
            cache_data['count'] += 1
            
            # Store back in cache with expiry set to the reset time
            ttl = int(cache_data['reset'] - time.time())
            cache.set(key, cache_data, ttl)
            
            # Check if rate limit exceeded
            if cache_data['count'] > limit:
                # Log rate limit breach
                logger.warning(
                    f"Rate limit exceeded: {key_prefix} by {scope}={key.split(':')[-1]}",
                    extra={
                        'key_prefix': key_prefix,
                        'scope': scope,
                        'limit': limit,
                        'period': period,
                        'count': cache_data['count'],
                        'client_ip': _get_client_ip(request),
                        'user_agent': request.META.get('HTTP_USER_AGENT', 'unknown'),
                    }
                )
                
                # Calculate retry-after time
                retry_after = int(cache_data['reset'] - time.time())
                
                # Raise throttled exception
                raise Throttled(
                    detail=f"Request rate limit exceeded. Try again in {retry_after} seconds.",
                    code='throttled'
                )
            
            # Execute the view function
            return view_func(request, *args, **kwargs)
        
        return wrapped_view
    
    return decorator

def login_rate_limit(view_func):
    """
    Specific rate limiter for login attempts.
    Stricter limits: 5 attempts per minute per IP, 10 attempts per hour per username
    """
    @rate_limit('login', limit=5, period=60, scope='ip')
    @functools.wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Apply username-specific rate limiting for POSTs (likely login attempts)
        if request.method == 'POST' and hasattr(request, 'data'):
            username = request.data.get('username') or request.data.get('email')
            if username:
                # Hash the username to avoid storing PII in cache keys
                username_hash = hashlib.sha256(username.lower().encode()).hexdigest()
                username_key = f"ratelimit:login:username_{username_hash}"
                
                # Get current username attempt count
                username_data = cache.get(username_key, {'count': 0, 'reset': time.time() + 3600})
                
                # Reset if period expired
                if time.time() > username_data['reset']:
                    username_data = {'count': 0, 'reset': time.time() + 3600}
                
                username_data['count'] += 1
                
                # Store back in cache
                ttl = int(username_data['reset'] - time.time())
                cache.set(username_key, username_data, ttl)
                
                # Check username rate limit - 10 attempts per hour
                if username_data['count'] > 10:
                    # Log username rate limit breach
                    logger.warning(
                        f"Username rate limit exceeded for hashed username: {username_hash}",
                        extra={
                            'username_hash': username_hash,
                            'count': username_data['count'],
                            'client_ip': _get_client_ip(request),
                        }
                    )
                    
                    # Calculate retry-after time
                    retry_after = int(username_data['reset'] - time.time())
                    
                    # Raise throttled exception
                    raise Throttled(
                        detail=f"Too many login attempts for this account. Try again in {retry_after} seconds.",
                        code='throttled'
                    )
        
        return view_func(request, *args, **kwargs)
    
    return wrapped_view

def reset_password_rate_limit(view_func):
    """
    Rate limiter specifically for password reset requests.
    Limits: 3 attempts per hour per email, 10 attempts per day per IP
    """
    @rate_limit('password_reset', limit=3, period=3600, scope='param')
    @rate_limit('password_reset_ip', limit=10, period=86400, scope='ip')
    @functools.wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Extract email from request for per-email rate limiting
        if request.method == 'POST' and hasattr(request, 'data'):
            email = request.data.get('email')
            if email:
                # Hash the email to avoid storing PII in cache keys
                kwargs['param_name'] = hashlib.sha256(email.lower().encode()).hexdigest()
        
        return view_func(request, *args, **kwargs)
    
    return wrapped_view

def registration_rate_limit(view_func):
    """
    Rate limiter for registration attempts to prevent spam account creation.
    Limits: 3 registrations per day per IP, 1 registration attempt per email per day
    """
    @rate_limit('registration', limit=3, period=86400, scope='ip')
    @functools.wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Apply email-specific rate limiting for POSTs
        if request.method == 'POST' and hasattr(request, 'data'):
            email = request.data.get('email')
            if email:
                # Hash the email to avoid storing PII in cache keys
                email_hash = hashlib.sha256(email.lower().encode()).hexdigest()
                email_key = f"ratelimit:registration:email_{email_hash}"
                
                # Get current email attempt count - 1 per day
                email_data = cache.get(email_key, {'count': 0, 'reset': time.time() + 86400})
                
                # Reset if period expired
                if time.time() > email_data['reset']:
                    email_data = {'count': 0, 'reset': time.time() + 86400}
                
                email_data['count'] += 1
                
                # Store back in cache
                ttl = int(email_data['reset'] - time.time())
                cache.set(email_key, email_data, ttl)
                
                # Check email rate limit - 1 attempt per email per day
                if email_data['count'] > 1:
                    logger.warning(
                        f"Registration rate limit exceeded for email hash: {email_hash}",
                        extra={
                            'email_hash': email_hash,
                            'client_ip': _get_client_ip(request),
                        }
                    )
                    
                    raise Throttled(
                        detail="An account with this email was recently registered or attempted. Please try again tomorrow.",
                        code='throttled'
                    )
        
        return view_func(request, *args, **kwargs)
    
    return wrapped_view

def api_key_rate_limit(limit=100, period=60):
    """
    Rate limiter for API key usage.
    Default: 100 requests per minute per API key
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Extract API key from request
            api_key = request.META.get('HTTP_X_API_KEY') or request.GET.get('api_key')
            
            if not api_key:
                # No API key provided, fallback to IP-based limiting
                return rate_limit('api', limit=10, period=60, scope='ip')(view_func)(request, *args, **kwargs)
            
            # Hash the API key for the cache key
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
            key = f"ratelimit:api:key_{key_hash}"
            
            # Get current count from cache
            cache_data = cache.get(key, {'count': 0, 'reset': time.time() + period})
            
            # Reset if period expired
            if time.time() > cache_data['reset']:
                cache_data = {'count': 0, 'reset': time.time() + period}
            
            cache_data['count'] += 1
            
            # Store back in cache
            ttl = int(cache_data['reset'] - time.time())
            cache.set(key, cache_data, ttl)
            
            # Check API key rate limit
            if cache_data['count'] > limit:
                logger.warning(
                    f"API key rate limit exceeded for key hash: {key_hash}",
                    extra={
                        'key_hash': key_hash,
                        'count': cache_data['count'],
                        'client_ip': _get_client_ip(request),
                    }
                )
                
                # Add rate limit headers
                headers = {
                    'X-RateLimit-Limit': str(limit),
                    'X-RateLimit-Remaining': '0',
                    'X-RateLimit-Reset': str(int(cache_data['reset'])),
                }
                
                # Calculate retry-after time
                retry_after = int(cache_data['reset'] - time.time())
                
                # Raise throttled exception with headers
                throttled = Throttled(
                    detail=f"API rate limit exceeded. Try again in {retry_after} seconds.",
                    code='throttled'
                )
                throttled.headers = headers
                raise throttled
            
            # Add rate limit headers to response
            response = view_func(request, *args, **kwargs)
            
            # Add rate limit headers
            response['X-RateLimit-Limit'] = str(limit)
            response['X-RateLimit-Remaining'] = str(max(0, limit - cache_data['count']))
            response['X-RateLimit-Reset'] = str(int(cache_data['reset']))
            
            return response
        
        return wrapped_view
    
    return decorator

def _get_client_ip(request):
    """Extract client IP from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
