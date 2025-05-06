#!/bin/bash

# Function to check if database is ready
function postgres_ready(){
python << END
import sys
import psycopg2
import os

try:
    dbname = os.environ.get("DB_NAME", "secure_auth_db")
    user = os.environ.get("DB_USER", "postgres")
    password = os.environ.get("DB_PASSWORD", "")
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    
    conn = psycopg2.connect(
        dbname=dbname,
        user=user,
        password=password,
        host=host,
        port=port
    )
except psycopg2.OperationalError:
    sys.exit(-1)
sys.exit(0)
END
}

# Wait for PostgreSQL to be ready
if [ "$USE_POSTGRES" = "True" ]; then
    echo "Waiting for PostgreSQL..."
    until postgres_ready; do
        echo "PostgreSQL unavailable, waiting..."
        sleep 2
    done
    echo "PostgreSQL ready!"
fi

# Change to Django project directory
cd Auth_backend

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Apply database migrations
echo "Applying database migrations..."
python manage.py migrate --noinput

# Create superuser if specified in environment variables
if [ -n "$DJANGO_SUPERUSER_EMAIL" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ]; then
    echo "Creating superuser..."
    python manage.py createsuperuser --noinput || echo "Superuser already exists"
fi

# Start Celery worker in the background if CELERY_WORKER=True
if [ "$CELERY_WORKER" = "True" ]; then
    echo "Starting Celery worker..."
    celery -A secure_auth worker --loglevel=info &
fi

# Start Celery beat in the background if CELERY_BEAT=True
if [ "$CELERY_BEAT" = "True" ]; then
    echo "Starting Celery beat..."
    celery -A secure_auth beat --loglevel=info &
fi

echo "Starting Django application..."
exec "$@"