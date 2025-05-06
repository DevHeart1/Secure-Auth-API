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

logger = logging.getLogger('authentication.security')

def custom_exception_handler(exc, context):
    """
    Custom exception handler for consistent API error responses.
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)

    if response is not None:
        data = {'error': str(exc)}
        
        # Add error detail for validation errors
        if isinstance(exc, ValidationError):
            data = {'error': 'Validation error', 'details': exc.detail}
            
        # Add request info for logging
        request = context.get('request')
        if request:
            # Log security-related exceptions
            if isinstance(exc, (AuthenticationFailed, NotAuthenticated, DRFPermissionDenied, Throttled)):
                log_data = {
                    'path': request.path,
                    'method': request.method,
                    'user': request.user.email if hasattr(request.user, 'email') else 'anonymous',
                    'ip': _get_client_ip(request),
                    'error_type': exc.__class__.__name__,
                    'error_detail': str(exc),
                }
                logger.warning(f"Security exception: {log_data}")
        
        # Replace response data with our custom format
        response.data = data
            
    else:
        # Handle Django and other exceptions
        if isinstance(exc, Http404):
            data = {'error': 'Resource not found'}
            response = Response(data, status=status.HTTP_404_NOT_FOUND)
            
        elif isinstance(exc, PermissionDenied):
            data = {'error': 'Permission denied'}
            response = Response(data, status=status.HTTP_403_FORBIDDEN)
            
        elif isinstance(exc, Exception):
            # Log unexpected errors
            logger.exception('Unexpected error')
            data = {'error': 'Internal server error'}
            response = Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return response

def _get_client_ip(request):
    """Extract client IP from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip