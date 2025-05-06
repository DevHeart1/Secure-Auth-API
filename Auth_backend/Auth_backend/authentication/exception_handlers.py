import logging
from django.http import Http404
from django.core.exceptions import PermissionDenied
from rest_framework.views import exception_handler
from rest_framework import status
from rest_framework.exceptions import (
    APIException,
    AuthenticationFailed,
    NotAuthenticated,
    ValidationError,
    PermissionDenied as DRFPermissionDenied,
    Throttled,
)
from rest_framework.response import Response
import traceback

logger = logging.getLogger('authentication.security')

def custom_exception_handler(exc, context):
    """
    Custom exception handler for DRF that provides consistent error responses
    with additional logging for security-related exceptions.
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    if response is None:
        # If DRF couldn't handle it, log it and return a generic 500
        logger.error(f"Unhandled exception: {exc.__class__.__name__}: {str(exc)}\n{traceback.format_exc()}")
        return Response(
            {"error": "An unexpected error occurred.", "code": "server_error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    # Add more context to the response
    error_data = {"error": str(exc)}
    
    # Add error code based on exception type
    if isinstance(exc, ValidationError):
        error_data["code"] = "validation_error"
        error_data["details"] = response.data
        
    elif isinstance(exc, AuthenticationFailed):
        error_data["code"] = "authentication_failed"
        # Log potential security incidents
        _log_security_event(exc, context)
        
    elif hasattr(exc, 'default_code'):
        error_data["code"] = exc.default_code
        
        # Log security-related exceptions
        if exc.default_code in ['permission_denied', 'not_authenticated', 'authentication_failed']:
            _log_security_event(exc, context)
    else:
        error_data["code"] = "api_error"
    
    # Replace the response data with our formatted data
    response.data = error_data
    
    return response

def _log_security_event(exc, context):
    """Log security-related exceptions with detailed context"""
    request = context['request']
    user = request.user
    
    log_data = {
        'exception': exc.__class__.__name__,
        'message': str(exc),
        'view': context['view'].__class__.__name__,
        'path': request.path,
        'method': request.method,
        'user': user.email if hasattr(user, 'email') and user.email else 'anonymous',
        'ip': _get_client_ip(request),
        'user_agent': request.META.get('HTTP_USER_AGENT', 'unknown'),
    }
    
    logger.warning(f"Security event detected: {log_data}")

def _get_client_ip(request):
    """Extract client IP from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip