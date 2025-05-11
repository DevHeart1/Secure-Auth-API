# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-05-11

### Added
- Initial production release
- Email-based authentication system with verification
- JWT authentication with refresh tokens
- OAuth2 social login (Google, GitHub)
- Password reset functionality
- Rate limiting for sensitive endpoints
- Brute-force protection
- User profile management endpoints
- Health check endpoints for monitoring
- Docker containerization with PostgreSQL, Redis, and Nginx
- Comprehensive API documentation
- Complete test suite with unit and integration tests

### Security
- bcrypt password hashing
- JWT with proper expiration and refresh token rotation
- HTTPS enforcement
- Comprehensive security headers
- Input validation and sanitization
