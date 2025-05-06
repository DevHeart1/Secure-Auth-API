 #!/bin/bash

set -e

# Function to wait for PostgreSQL to be ready
function postgres_ready() {
python << END
import sys
import psycopg2
import os

try:
    conn = psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT", "5432"),
    )
except psycopg2.OperationalError:
    sys.exit(1)
sys.exit(0)
END
}

# Wait for PostgreSQL
until postgres_ready; do
    echo "Waiting for PostgreSQL..."
    sleep 2
done
echo "PostgreSQL is ready!"

# Apply database migrations
echo "Applying database migrations..."
cd Auth_backend
python manage.py migrate

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Create superuser if not exists (only in development)
if [[ "$DJANGO_SETTINGS_MODULE" != *prod* ]]; then
    echo "Creating superuser if not exists..."
    python manage.py createsuperuser --noinput || true
fi

exec "$@"