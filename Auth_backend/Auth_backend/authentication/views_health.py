from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
import psycopg2
import redis
import os
from django.conf import settings
from django.db import connections
from django.db.utils import OperationalError

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    A simple health check endpoint to verify the API is running
    """
    health_data = {
        'status': 'healthy',
        'database': check_database(),
        'cache': check_redis() if settings.DEBUG is False else 'not_checked',
    }
    
    # If any check failed, return 503 Service Unavailable
    if 'unhealthy' in health_data.values():
        return Response(health_data, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    
    return Response(health_data)

def check_database():
    """Check if database connection is working"""
    try:
        # Try to connect to database
        db_conn = connections['default']
        db_conn.cursor()
        return 'healthy'
    except OperationalError:
        return 'unhealthy'

def check_redis():
    """Check if Redis connection is working"""
    try:
        redis_url = os.getenv('REDIS_URL', 'redis://redis:6379/1')
        r = redis.from_url(redis_url)
        r.ping()
        return 'healthy'
    except (redis.exceptions.ConnectionError, redis.exceptions.ResponseError):
        return 'unhealthy'