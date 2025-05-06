#!/bin/bash

# Setup script for Secure Auth API initial deployment
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Secure Auth API setup...${NC}"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Docker Compose is not installed. Please install Docker Compose first.${NC}"
    exit 1
fi

# Check if .env file exists, if not create it from example
if [ ! -f .env ]; then
    echo -e "${YELLOW}.env file not found. Creating from .env.example...${NC}"
    if [ -f .env.example ]; then
        cp .env.example .env
        echo -e "${GREEN}.env file created. Please update it with your configuration.${NC}"
    else
        echo -e "${RED}.env.example file not found. Please create a .env file manually.${NC}"
        exit 1
    fi

    # Generate a secure secret key
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')
    sed -i "s/your-very-secure-secret-key-should-be-at-least-50-characters/$SECRET_KEY/g" .env
    echo -e "${GREEN}Generated secure SECRET_KEY for your application.${NC}"
fi

# Create directories for logs, ssl, etc.
echo -e "${GREEN}Creating necessary directories...${NC}"
mkdir -p logs nginx/ssl Auth_backend/logs

# Create self-signed SSL certificate for development
if [ ! -f nginx/ssl/cert.pem ] || [ ! -f nginx/ssl/key.pem ]; then
    echo -e "${YELLOW}Generating self-signed SSL certificate for development...${NC}"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/key.pem -out nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    echo -e "${GREEN}Self-signed SSL certificate created.${NC}"
fi

# Build the Docker containers
echo -e "${GREEN}Building Docker containers...${NC}"
docker-compose build

echo -e "${GREEN}Setup completed successfully.${NC}"
echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Edit the ${YELLOW}.env${NC} file with your configuration settings"
echo -e "2. Run ${YELLOW}docker-compose up -d${NC} to start the application"
echo -e "3. Access the API at ${YELLOW}https://localhost/api/v1/auth/${NC}"
echo -e "4. Access the API documentation at ${YELLOW}https://localhost/api/docs/${NC}"