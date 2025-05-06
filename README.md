# Secure Authentication API

A production-ready authentication API with enterprise-grade security features, built using Django REST Framework, JWT tokens, and OAuth2 providers.

## Features

- **Secure User Management**
  - Email-based authentication
  - Strong password policies
  - Account verification via email
  - Password reset functionality
  - JWT-based authentication with refresh tokens

- **OAuth2 Social Login**
  - Google authentication
  - GitHub authentication
  - Extensible for other providers

- **Security Measures**
  - bcrypt password hashing
  - Rate limiting for sensitive endpoints
  - Brute-force protection
  - JWT with proper expiration and refresh token rotation
  - HTTPS enforcement
  - Comprehensive security headers

- **Production Ready**
  - Docker containerization
  - PostgreSQL database integration
  - Redis for caching and task queue
  - Nginx for reverse proxy and SSL termination
  - Celery for asynchronous tasks
  - Monitoring and health checks

- **Comprehensive Testing**
  - Unit tests for models, serializers, and views
  - Integration tests for API endpoints
  - CI/CD pipeline integration

## Getting Started

### Prerequisites

- Docker and Docker Compose
- GNU Make (optional, for using Makefile commands)

### Quick Start

1. Clone the repository
   ```
   git clone https://github.com/DevHeart1/Secure-Auth-API.git
   cd Secure-Auth-API/Auth_backend
   ```

2. Run the setup script
   ```
   chmod +x setup.sh
   ./setup.sh
   ```

3. Start the application
   ```
   docker-compose up -d
   ```

4. Access the API at `https://localhost/api/v1/auth/`
   - API documentation: `https://localhost/api/docs/`

### Environment Variables

Create a `.env` file in the Auth_backend directory with the following variables:

```
# Copy from .env.example and modify as needed
cp .env.example .env
```

Key environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key | Auto-generated |
| `DEBUG` | Debug mode | `False` |
| `ALLOWED_HOSTS` | Allowed hosts | `localhost` |
| `DB_*` | Database settings | Postgres settings |
| `EMAIL_*` | Email settings | SMTP settings |
| `GOOGLE_OAUTH2_*` | Google OAuth2 settings | - |
| `GITHUB_OAUTH2_*` | GitHub OAuth2 settings | - |

## API Endpoints

### Authentication

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|--------------|
| `/api/v1/auth/register/` | POST | Register a new user | No |
| `/api/v1/auth/verify-email/` | POST | Verify email address | No |
| `/api/v1/auth/login/` | POST | Login and get tokens | No |
| `/api/v1/auth/token/refresh/` | POST | Refresh access token | No |
| `/api/v1/auth/password-reset-request/` | POST | Request password reset | No |
| `/api/v1/auth/password-reset-confirm/` | POST | Confirm password reset | No |
| `/api/v1/auth/profile/` | GET/PATCH | Get or update profile | Yes |
| `/api/v1/auth/google_auth/` | POST | Google OAuth login | No |
| `/api/v1/auth/github_auth/` | POST | GitHub OAuth login | No |
| `/api/v1/auth/health/` | GET | API health check | No |

### Sample Requests

#### User Registration

```json
POST /api/v1/auth/register/
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "password_confirm": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Email Verification

```json
POST /api/v1/auth/verify-email/
{
  "token": "verification-token-from-email"
}
```

#### User Login

```json
POST /api/v1/auth/login/
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

Response:
```json
{
  "access": "jwt-access-token",
  "refresh": "jwt-refresh-token",
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

#### Token Refresh

```json
POST /api/v1/auth/token/refresh/
{
  "refresh": "jwt-refresh-token"
}
```

#### Get User Profile

```
GET /api/v1/auth/profile/
Authorization: Bearer jwt-access-token
```

## Development

### Running Tests

```bash
cd Auth_backend
python -m pytest
```

With coverage report:
```bash
cd Auth_backend
python -m pytest --cov=authentication --cov-report=html
```

### Code Style and Linting

```bash
cd Auth_backend
flake8 .
black .
isort .
```

## Deployment

### Production Setup

1. Set up your production server with Docker and Docker Compose
2. Update the `.env` file with production values
3. Run the application with `docker-compose -f docker-compose.yml up -d`

### Security Considerations

- Use a properly configured SSL certificate in production
- Regularly rotate the Django `SECRET_KEY`
- Keep all packages updated to their latest versions
- Monitor authentication logs for suspicious activity
- Consider implementing additional security measures like IP-based throttling

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -am 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Django REST Framework
- SimpleJWT
- bcrypt
- OAuth2 providers
