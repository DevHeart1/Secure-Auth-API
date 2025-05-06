import time
from functools import wraps
from django.conf import settings
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework import status
import logging

# Configure logger
logger = logging.getLogger('authentication.security')

def rate_limit(key_prefix, limit=5, period=60, limit_response=None):
    """
    Rate limiting decorator for views
    
    Args:
        key_prefix (str): Prefix for the cache key
        limit (int): Maximum number of requests allowed in the period
        period (int): Time period in seconds
        limit_response: Response to return when rate limit is exceeded
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Get client IP
            ip_address = get_client_ip(request)
            
            # Create cache key based on IP and endpoint
            cache_key = f"{key_prefix}:{ip_address}"
            
            # Get current request count for this key
            requests = cache.get(cache_key, [])
            
            # Filter out requests older than the specified period
            current_time = time.time()
            requests = [req_time for req_time in requests if current_time - req_time < period]
            
            # Check if rate limit is exceeded
            if len(requests) >= limit:
                logger.warning(f"Rate limit exceeded for {cache_key}")
                
                # Use custom response if provided, otherwise return default
                if limit_response:
                    return limit_response
                return Response(
                    {"error": "Rate limit exceeded. Please try again later."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            
            # Add current request timestamp and update cache
            requests.append(current_time)
            cache.set(cache_key, requests, period * 2)  # Set cache expiry to twice the period
            
            # Call the original view function
            return view_func(request, *args, **kwargs)
        
        return _wrapped_view
    
    return decorator

def get_client_ip(request):
    """Get client IP address from request headers"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip