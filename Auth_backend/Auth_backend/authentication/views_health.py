"""
Health check endpoints for the authentication API.
These endpoints are used by monitoring systems to verify the API is functioning.
"""
import logging
import time
from django.db import connection
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.core.cache import cache
from django.utils import timezone
import redis
import psutil
import os

logger = logging.getLogger('authentication')

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Basic health check endpoint that verifies the API is running.
    Returns 200 OK if the API is functioning normally.
    """
    start_time = time.time()
    health_status = {
        'status': 'ok',
        'timestamp': timezone.now().isoformat(),
        'components': {},
        'info': {
            'version': getattr(settings, 'API_VERSION', 'unknown'),
            'environment': getattr(settings, 'ENVIRONMENT', 'production'),
        }
    }
    
    # Check database connection
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        health_status['components']['database'] = {
            'status': 'up'
        }
    except Exception as e:
        health_status['status'] = 'degraded'
        health_status['components']['database'] = {
            'status': 'down',
            'error': str(e)
        }
        logger.error(f"Health check database error: {e}")
    
    # Check cache connection
    try:
        cache_key = 'health_check'
        cache_value = f'health_{timezone.now().timestamp()}'
        cache.set(cache_key, cache_value, 10)
        retrieved_value = cache.get(cache_key)
        
        if retrieved_value == cache_value:
            health_status['components']['cache'] = {
                'status': 'up'
            }
        else:
            health_status['status'] = 'degraded'
            health_status['components']['cache'] = {
                'status': 'degraded',
                'error': 'Cache retrieval mismatch'
            }
    except Exception as e:
        health_status['status'] = 'degraded'
        health_status['components']['cache'] = {
            'status': 'down',
            'error': str(e)
        }
        logger.error(f"Health check cache error: {e}")
    
    # Check Redis connection (if using Redis)
    if hasattr(settings, 'REDIS_URL') and settings.REDIS_URL:
        try:
            redis_client = redis.from_url(settings.REDIS_URL)
            redis_client.ping()
            health_status['components']['redis'] = {
                'status': 'up'
            }
        except Exception as e:
            health_status['status'] = 'degraded'
            health_status['components']['redis'] = {
                'status': 'down',
                'error': str(e)
            }
            logger.error(f"Health check Redis error: {e}")
    
    # Add system info
    try:
        health_status['info']['system'] = {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
        }
    except Exception as e:
        # Non-critical, just log
        logger.warning(f"Could not get system info: {e}")
    
    # Calculate response time
    end_time = time.time()
    health_status['response_time_ms'] = round((end_time - start_time) * 1000, 2)
    
    if health_status['status'] == 'degraded':
        return Response(health_status, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    
    return Response(health_status)

@api_view(['GET'])
@permission_classes([AllowAny])
def readiness_check(request):
    """
    Readiness check endpoint for Kubernetes/load balancers.
    Verifies if the service is ready to accept traffic.
    """
    # Simple check - if we can respond, we're ready
    return Response({'status': 'ready'})

@api_view(['GET'])
@permission_classes([AllowAny])
def liveness_check(request):
    """
    Liveness check endpoint for Kubernetes.
    Verifies if the service is still alive and should not be restarted.
    """
    # Simple check - if we can respond, we're alive
    return Response({'status': 'alive'})