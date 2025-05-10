"""
Production settings for secure_auth project.
These settings extend the base settings with production-specific configurations.
"""

import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.celery import CeleryIntegration
import os
from datetime import timedelta

from .settings import *  # Import base settings

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# Domain configuration
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'api.yourdomain.com').split(',')
CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', 'https://yourdomain.com').split(',')
CSRF_TRUSTED_ORIGINS = os.getenv('CSRF_TRUSTED_ORIGINS', 'https://api.yourdomain.com').split(',')

# Database
# Use PostgreSQL in production
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'secure_auth_db'),
        'USER': os.getenv('DB_USER', 'secure_auth_user'),
        'PASSWORD': os.getenv('DB_PASSWORD', ''),
        'HOST': os.getenv('DB_HOST', 'postgres'),
        'PORT': os.getenv('DB_PORT', '5432'),
        'OPTIONS': {
            'sslmode': os.getenv('DB_SSL_MODE', 'prefer'),
            'connect_timeout': 10,
        },
    }
}

# Cache settings
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.getenv('REDIS_URL', 'redis://redis:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'CONNECTION_POOL_KWARGS': {'max_connections': 100},
            'PARSER_CLASS': 'redis.connection.HiredisParser',
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
        }
    }
}

# Session settings - use Redis and secure cookies
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 86400  # 24 hours

# CSRF settings
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = [f'https://{host}' for host in ALLOWED_HOSTS]

# Security settings
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Password validation - stricter for production
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 10,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Email configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.getenv('EMAIL_HOST')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True') == 'True'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'no-reply@yourdomain.com')
SERVER_EMAIL = os.getenv('SERVER_EMAIL', 'server@yourdomain.com')

# JWT settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'JTI_CLAIM': 'jti',
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=15),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=7),
}

# Media and static files
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Logging
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
        'json': {
            'format': '{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "name": "%(name)s", "path": "%(pathname)s", "lineno": %(lineno)d}',
            'datefmt': '%Y-%m-%dT%H:%M:%S%z',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'json',
        },
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler',
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOGS_DIR, 'secure_auth.log'),
            'maxBytes': 1024 * 1024 * 10,  # 10 MB
            'backupCount': 10,
            'formatter': 'json',
        },
        'security_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOGS_DIR, 'security.log'),
            'maxBytes': 1024 * 1024 * 10,  # 10 MB
            'backupCount': 10,
            'formatter': 'json',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file', 'mail_admins'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.server': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['security_file', 'mail_admins'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['file', 'mail_admins'],
            'level': 'INFO',
            'propagate': False,
        },
        'authentication': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True,
        },
        'authentication.security': {
            'handlers': ['security_file', 'mail_admins'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Sentry configuration
sentry_sdk.init(
    dsn=os.getenv('SENTRY_DSN', ''),
    integrations=[
        DjangoIntegration(),
        RedisIntegration(),
        CeleryIntegration(),
    ],
    traces_sample_rate=float(os.getenv('SENTRY_TRACES_SAMPLE_RATE', '0.1')),
    send_default_pii=False,
    environment=os.getenv('SENTRY_ENVIRONMENT', 'production'),
)

# Celery configuration
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_TIME_LIMIT = 60 * 5  # 5 minutes
CELERY_TASK_SOFT_TIME_LIMIT = 60 * 3  # 3 minutes

# Frontend URL
FRONTEND_URL = os.getenv('FRONTEND_URL', 'https://yourdomain.com')

# OAuth2 settings
GOOGLE_OAUTH2_CLIENT_ID = os.getenv('GOOGLE_OAUTH2_CLIENT_ID')
GOOGLE_OAUTH2_CLIENT_SECRET = os.getenv('GOOGLE_OAUTH2_CLIENT_SECRET')
GITHUB_OAUTH2_CLIENT_ID = os.getenv('GITHUB_OAUTH2_CLIENT_ID')
GITHUB_OAUTH2_CLIENT_SECRET = os.getenv('GITHUB_OAUTH2_CLIENT_SECRET')

# Admins for error emails
ADMINS = [tuple(admin.split(':')) for admin in os.getenv('ADMINS', 'Admin:admin@yourdomain.com').split(',')]

# Rate limiting
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_ENABLE = True
RATELIMIT_FAIL_OPEN = False  # Fail closed (deny requests) when Redis is unavailable

# Prometheus metrics configuration
if os.environ.get('ENABLE_PROMETHEUS_METRICS', 'False') == 'True':
    INSTALLED_APPS += ['django_prometheus']
    MIDDLEWARE = ['django_prometheus.middleware.PrometheusBeforeMiddleware'] + MIDDLEWARE
    MIDDLEWARE = MIDDLEWARE + ['django_prometheus.middleware.PrometheusAfterMiddleware']

# Ensure ALLOWED_HOSTS is properly set
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')
if not ALLOWED_HOSTS:
    raise Exception("ALLOWED_HOSTS environment variable must be set in production")

# Always use SSL in production
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Static files
STATIC_ROOT = '/app/staticfiles'
MEDIA_ROOT = '/app/media'

# Make sure log directories exist
os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)

# Email settings - ensure these are properly configured in production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
if not all([os.environ.get('EMAIL_HOST'), 
           os.environ.get('EMAIL_HOST_USER'), 
           os.environ.get('EMAIL_HOST_PASSWORD')]):
    raise Exception("Email settings must be properly configured in production")

# Set API version
API_VERSION = os.environ.get('API_VERSION', '1.0.0')

# Set environment name
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')

# Increase token security in production
SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'] = timedelta(minutes=15)
SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'] = timedelta(days=7)
SIMPLE_JWT['ALGORITHM'] = 'HS512'  # More secure algorithm
SIMPLE_JWT['AUTH_TOKEN_CLASSES'] = ('rest_framework_simplejwt.tokens.AccessToken',)
SIMPLE_JWT['AUTH_HEADER_NAME'] = 'HTTP_AUTHORIZATION'
SIMPLE_JWT['JTI_CLAIM'] = 'jti'

# Set allowed origins for CORS in production
if not CORS_ALLOWED_ORIGINS:
    raise Exception("CORS_ALLOWED_ORIGINS environment variable must be set in production")

# Sentry configuration for error tracking (if available)
if os.environ.get('SENTRY_DSN'):
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration

    sentry_sdk.init(
        dsn=os.environ.get('SENTRY_DSN'),
        integrations=[DjangoIntegration()],
        traces_sample_rate=float(os.environ.get('SENTRY_TRACES_SAMPLE_RATE', '0.1')),
        send_default_pii=False,
        environment=ENVIRONMENT,
        release=API_VERSION
    )