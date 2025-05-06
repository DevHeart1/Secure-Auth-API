import logging
import traceback
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.http import Http404
from django.core.exceptions import PermissionDenied
from django.db.models import ProtectedError
from rest_framework_simplejwt.exceptions import AuthenticationFailed, InvalidToken

# Configure logger
logger = logging.getLogger('authentication.security')

def custom_exception_handler(exc, context):
    """
    Custom exception handler for consistent API error responses
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)

    # If unexpected error occurs (not caught by DRF's exception handler)
    if response is None:
        # Log the error with traceback
        logger.error(f"Unhandled exception: {str(exc)}\n{traceback.format_exc()}")
        
        # Generic error message for unexpected errors
        error_message = "An unexpected error occurred. Our team has been notified."
        
        # Customize based on exception type for common exceptions
        if isinstance(exc, Http404):
            status_code = status.HTTP_404_NOT_FOUND
            error_message = "The requested resource was not found."
        elif isinstance(exc, PermissionDenied):
            status_code = status.HTTP_403_FORBIDDEN
            error_message = "You do not have permission to perform this action."
        elif isinstance(exc, ProtectedError):
            status_code = status.HTTP_400_BAD_REQUEST
            error_message = "This object cannot be deleted because it is referenced by other objects."
        else:
            # Default to 500 for truly unexpected errors
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

        # Return a consistent error response
        return Response(
            {"error": error_message},
            status=status_code
        )
    
    # Handle JWT authentication errors specifically
    if isinstance(exc, (AuthenticationFailed, InvalidToken)):
        logger.info(f"Authentication error: {str(exc)}", extra={
            'path': context['request'].path,
            'method': context['request'].method,
            'error': str(exc)
        })

    # Handle normal errors caught by DRF (keep original status but standardize format)
    # Transform the error data to match our format
    if response is not None:
        error_data = {}
        if isinstance(response.data, dict):
            # Handle dictionary-style errors
            if 'detail' in response.data:
                error_data['message'] = response.data['detail']
                # Remove detail to avoid duplication
                del response.data['detail']
            
            if response.data and response.data != {'detail': error_data.get('message', '')}:
                error_data['errors'] = response.data
        elif isinstance(response.data, list):
            error_data['message'] = "Multiple errors occurred."
            error_data['errors'] = response.data
        else:
            error_data['message'] = str(response.data)

        # Replace the response data with our standardized format
        response.data = error_data
    
    return response