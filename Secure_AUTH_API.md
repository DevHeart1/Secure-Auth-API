# Secure Auth API - Comprehensive Documentation

**Version:** 1.0.0 (Draft)
**Last Updated:** May 5, 2025

## 1. Overview

### 1.1. Introduction

Secure-Auth-API provides a robust, secure, and scalable backend solution for managing user authentication and authorization. Designed with modern security best practices at its core, it handles user registration, login (traditional and social), password management, email verification, and session control using JSON Web Tokens (JWT). This API serves as a foundational identity layer for web and mobile applications, prioritizing security, developer experience, and performance.

### 1.2. Goals

*   Provide a secure, reliable, and easy-to-integrate authentication system.
*   Implement industry-standard authentication flows (Credentials, OAuth2).
*   Protect against common web vulnerabilities and attack vectors (OWASP Top 10 relevant threats).
*   Offer clear API contracts and comprehensive documentation.
*   Ensure scalability and maintainability.

### 1.3. Target Audience

This documentation is intended for developers integrating with the Secure-Auth-API, including frontend developers, backend developers consuming the API, and system administrators responsible for deployment and maintenance.

## 2. Core Features

*   **User Account Management:**
    *   Secure user registration with email and password.
    *   Email uniqueness enforcement.
    *   Password complexity enforcement (configurable).
*   **Authentication Mechanisms:**
    *   Credentials-based login (email/password).
    *   Stateless session management using JWT (Access & Refresh Tokens).
    *   OAuth2 integration for social logins (Google, GitHub).
*   **Security & Protection:**
    *   Password hashing using `bcrypt` (or Argon2).
    *   Rate limiting on critical endpoints (login, signup, password reset).
    *   Brute-force attack mitigation (e.g., login attempt tracking, account lockout).
    *   Secure password reset flow via email tokens.
    *   Email verification process to confirm user identity.
    *   Protection against common vulnerabilities (e.g., input validation).
*   **API Design:**
    *   RESTful API principles.
    *   Clear and consistent JSON request/response formats.
    *   Standard HTTP status codes for outcomes.

## 3. Architecture & Technology Stack (Conceptual)

*(This section outlines the proposed technologies. The final implementation might vary.)*

*   **Programming Language/Framework:** Python / Django (Chosen for its built-in security features, ORM, and rapid development capabilities)
    *   *Alternatives:* Node.js/Express, Go/Gin, Ruby/Rails
*   **Database:** PostgreSQL (Relational, robust, good for structured user data)
    *   *Alternatives:* MySQL, MongoDB (if less structure is needed)
*   **Authentication Libraries:**
    *   `djangorestframework-simplejwt` (for JWT handling)
    *   `python-social-auth` or `django-allauth` (for OAuth2 integration)
*   **Password Hashing:** `bcrypt` (Django's default, strong and widely adopted)
*   **Rate Limiting:** `django-ratelimit` or custom middleware using Redis/Memcached.
*   **Asynchronous Tasks:** Celery with Redis/RabbitMQ (for sending emails non-blockingly).
*   **Email Service:** SendGrid, Mailgun, or AWS SES (for reliable email delivery).
*   **Caching:** Redis or Memcached (for rate limiting counters, session data if needed).

## 4. API Endpoint Definitions

**Base URL:** `/api/v1`

*(Note: All endpoints returning sensitive data or requiring authentication expect an `Authorization: Bearer <access_token>` header unless otherwise specified.)*

---

### 4.1. Authentication (`/auth`)

#### `POST /auth/signup`
*   **Description:** Registers a new user account. Sends a verification email.
*   **Request Body:**
    ```json
    {
      "email": "user@example.com", // Required, valid email format
      "password": "SecureP@ssw0rd!", // Required, meets complexity rules
      "first_name": "John", // Optional
      "last_name": "Doe" // Optional
    }
    ```
*   **Success Response (201 Created):**
    ```json
    {
      "message": "Account created successfully. Please check your email to verify your account.",
      "user_id": 123 // Optional: ID of the created user
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Invalid input (e.g., invalid email, weak password, missing fields). Body contains specific error details.
    *   `409 Conflict`: Email address already exists.

#### `POST /auth/login`
*   **Description:** Authenticates a user and returns JWT access and refresh tokens. Requires a verified email address.
*   **Request Body:**
    ```json
    {
      "email": "user@example.com", // Required
      "password": "SecureP@ssw0rd!" // Required
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", // Short-lived Access Token
      "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." // Longer-lived Refresh Token
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Missing fields.
    *   `401 Unauthorized`: Invalid credentials or email not verified.
    *   `429 Too Many Requests`: Rate limit exceeded.

#### `POST /auth/token/refresh`
*   **Description:** Obtains a new access token using a valid refresh token.
*   **Request Body:**
    ```json
    {
      "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." // Required, valid Refresh Token
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." // New Access Token
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Missing refresh token.
    *   `401 Unauthorized`: Invalid or expired refresh token.

#### `POST /auth/verify-email`
*   **Description:** Verifies a user's email address using a token sent during signup.
*   **Request Body:**
    ```json
    {
      "token": "unique_verification_token_from_email" // Required
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "message": "Email verified successfully. You can now log in."
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Missing token.
    *   `404 Not Found`: Invalid or expired token.

#### `POST /auth/resend-verification`
*   **Description:** Resends the email verification link to a user's email address.
*   **Request Body:**
    ```json
    {
      "email": "user@example.com" // Required
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "message": "Verification email resent successfully."
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Missing email.
    *   `404 Not Found`: Email not found or already verified.
    *   `429 Too Many Requests`: Rate limit exceeded.

#### `POST /auth/password/reset`
*   **Description:** Initiates the password reset process by sending a reset link/token to the user's email.
*   **Request Body:**
    ```json
    {
      "email": "user@example.com" // Required
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "message": "If an account with that email exists, a password reset link has been sent."
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Missing email.
    *   `404 Not Found`: (Optional, often omitted for security) Email not found.
    *   `429 Too Many Requests`: Rate limit exceeded.
    *(Note: Response is often generic to prevent email enumeration)*

#### `POST /auth/password/reset/confirm`
*   **Description:** Sets a new password using the token received via email.
*   **Request Body:**
    ```json
    {
      "token": "unique_password_reset_token", // Required
      "new_password": "NewSecureP@ssw0rd!" // Required, meets complexity rules
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "message": "Password has been reset successfully."
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Missing fields, weak password, invalid/expired token.

---

### 4.2. OAuth2 Social Login (`/auth`)

#### `GET /auth/google`
*   **Description:** Redirects the user to Google's OAuth2 consent screen.
*   **Response:** `302 Found` redirect to Google's authentication URL.

#### `GET /auth/google/callback`
*   **Description:** Callback URL where Google redirects after user authentication. The API exchanges the received code for Google tokens, fetches user info, creates/logs in the user, and issues JWTs.
*   **Query Parameters (from Google):** `code`, `state` (optional)
*   **Success Response:** Typically redirects the user back to the frontend application with JWTs embedded in the URL fragment (`#access=...&refresh=...`) or sets secure HTTP-only cookies. The exact mechanism depends on the frontend integration strategy.
*   **Error Response:** Redirects back to the frontend with error information in the URL query parameters (e.g., `?error=google_auth_failed`).

#### `GET /auth/github`
*   **Description:** Redirects the user to GitHub's OAuth2 consent screen.
*   **Response:** `302 Found` redirect to GitHub's authentication URL.

#### `GET /auth/github/callback`
*   **Description:** Callback URL where GitHub redirects after user authentication. Similar flow to Google callback.
*   **Query Parameters (from GitHub):** `code`, `state` (optional)
*   **Success Response:** Similar to Google callback (redirect with tokens/cookies).
*   **Error Response:** Similar to Google callback (redirect with error).

---

### 4.3. User Profile (`/users`)

#### `GET /users/me`
*   **Description:** Retrieves the profile information of the currently authenticated user.
*   **Requires Authentication:** Yes (`Authorization: Bearer <access_token>`)
*   **Success Response (200 OK):**
    ```json
    {
      "id": 123,
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "is_verified": true,
      "date_joined": "2025-01-15T10:30:00Z"
      // Add other relevant user fields
    }
    ```
*   **Error Responses:**
    *   `401 Unauthorized`: Invalid or missing access token.

#### `PATCH /users/me`
*   **Description:** Updates the profile information of the currently authenticated user.
*   **Requires Authentication:** Yes (`Authorization: Bearer <access_token>`)
*   **Request Body:** (Include only fields to be updated)
    ```json
    {
      "first_name": "Jonathan", // Optional
      "last_name": "Doer" // Optional
      // Other updatable fields
    }
    ```
*   **Success Response (200 OK):** Returns the updated user profile (similar to `GET /users/me`).
*   **Error Responses:**
    *   `400 Bad Request`: Invalid input data.
    *   `401 Unauthorized`: Invalid or missing access token.

---

## 5. Authentication & Authorization Flows

### 5.1. JWT Handling
*   **Access Token:** Short-lived (e.g., 15 minutes). Used in the `Authorization: Bearer <token>` header for accessing protected resources. Contains user identifier and potentially basic roles/permissions.
*   **Refresh Token:** Longer-lived (e.g., 7 days, 30 days). Stored securely by the client (e.g., HTTP-only cookie or secure local storage). Used solely to request new access tokens via the `/auth/token/refresh` endpoint. Refresh tokens can be invalidated on logout or if compromised. Consider implementing refresh token rotation for enhanced security.
*   **Storage:** Recommend storing refresh tokens in secure, HTTP-only cookies to mitigate XSS attacks. Access tokens can be stored in memory.

### 5.2. Signup & Email Verification Flow
1.  Client sends `POST /auth/signup` request with user details.
2.  API validates data, checks for existing email.
3.  API creates a user record (marked as `is_verified=false`).
4.  API generates a unique, time-limited verification token, stores it (associated with the user), and triggers an asynchronous task to send a verification email containing a link like `https://yourfrontend.com/verify-email?token=<token>`.
5.  Client receives `201 Created` response.
6.  User clicks the link in the email.
7.  Frontend extracts the token and sends `POST /auth/verify-email` with the token.
8.  API validates the token (checks existence, expiry, and association).
9.  If valid, API marks the user as `is_verified=true` and invalidates the token.
10. Client receives `200 OK` response. User can now log in.

### 5.3. Login Flow
1.  Client sends `POST /auth/login` with email and password.
2.  API validates credentials.
3.  API checks if the user exists and the password matches the stored hash.
4.  API checks if the user's email is verified (`is_verified=true`). If not, return `401 Unauthorized` with an appropriate error message.
5.  If credentials are valid and email is verified, API generates JWT access and refresh tokens.
6.  API returns `200 OK` with the tokens in the response body.
7.  Client securely stores the tokens (e.g., access token in memory, refresh token in HTTP-only cookie).

### 5.4. Password Reset Flow
1.  Client sends `POST /auth/password/reset` with the user's email.
2.  API generates a unique, time-limited password reset token, stores it, and triggers an email send task with a link like `https://yourfrontend.com/reset-password?token=<token>`. (Always return a generic success message regardless of email existence).
3.  User clicks the link.
4.  Frontend displays a form for the new password and sends `POST /auth/password/reset/confirm` with the token and new password.
5.  API validates the token and the new password's complexity.
6.  If valid, API updates the user's password hash and invalidates the reset token.
7.  Client receives `200 OK`.

### 5.5. OAuth2 Flow (Conceptual - Google Example)
1.  Client directs the user to `GET /auth/google`.
2.  API redirects the user to Google's OAuth2 consent screen.
3.  User authenticates with Google and grants permission.
4.  Google redirects the user back to the API's configured callback URL (`GET /auth/google/callback`) with an authorization `code`.
5.  API receives the `code`.
6.  API makes a server-to-server request to Google to exchange the `code` for Google access/refresh tokens.
7.  API uses Google's access token to request the user's profile information (email, name, etc.) from Google's API.
8.  API checks if a user with this email already exists:
    *   **Existing User:** Log them in.
    *   **New User:** Create a new user account (mark as verified, as Google verifies emails).
9.  API generates its own JWT access and refresh tokens for the user.
10. API redirects the user back to the frontend application, passing the JWTs (e.g., via URL fragment or cookies).

## 6. Security Best Practices Implemented

*   **HTTPS Enforcement:** The API should only be accessible over HTTPS. Use HSTS headers.
*   **Password Security:**
    *   Strong hashing algorithm (`bcrypt` or `Argon2`).
    *   Password complexity requirements enforced on signup and password reset.
    *   Never store passwords in plain text.
*   **Rate Limiting:** Applied to login, signup, password reset requests, and potentially token refresh endpoints to prevent automated abuse. Uses algorithms like Token Bucket or Leaky Bucket, often tracked by IP address and/or user ID.
*   **Brute-Force Protection:** Track failed login attempts per account and/or IP. Implement temporary lockouts or CAPTCHA challenges after exceeding a threshold.
*   **JWT Security:**
    *   Use strong, secret keys (stored securely, not in code).
    *   Short expiry for access tokens.
    *   Implement refresh token rotation and secure storage (HTTP-only cookies recommended).
    *   Include `aud` (audience) and `iss` (issuer) claims.
    *   Mechanism to blacklist tokens if needed (e.g., on logout, password change).
*   **OAuth2 Security:**
    *   Use the `state` parameter to prevent CSRF attacks during the OAuth flow.
    *   Validate tokens received from providers.
    *   Store client secrets securely.
*   **Input Validation:** Rigorously validate and sanitize all incoming data (request bodies, query parameters, headers) to prevent injection attacks (SQLi, XSS).
*   **Secure Headers:** Implement security headers like `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.
*   **Email Verification & Password Reset Tokens:** Ensure tokens are unique, cryptographically strong, time-limited, and single-use.
*   **Dependency Management:** Regularly scan dependencies for known vulnerabilities.
*   **Least Privilege:** Ensure API processes run with the minimum necessary permissions.

## 7. Setup and Installation Guide

### 7.1. Prerequisites
*   Python (e.g., 3.10+) & Pip
*   PostgreSQL Server
*   Redis (Optional, for caching/rate limiting/Celery)
*   Git

### 7.2. Installation Steps
```bash
# 1. Clone the repository
git clone <repository-url>
cd Secure-Auth-API

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate # On Windows use `venv\Scripts\activate`

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure Environment Variables
cp .env.example .env
# --> Edit the .env file with your settings: <--
#    - DATABASE_URL (e.g., postgresql://user:password@host:port/dbname)
#    - SECRET_KEY (Generate a strong random key)
#    - JWT_SECRET_KEY (Generate another strong random key)
#    - ALLOWED_HOSTS
#    - CORS_ALLOWED_ORIGINS (Your frontend URL)
#    - EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, EMAIL_USE_TLS
#    - GOOGLE_OAUTH2_KEY, GOOGLE_OAUTH2_SECRET
#    - GITHUB_OAUTH2_KEY, GITHUB_OAUTH2_SECRET
#    - REDIS_URL (if using Redis)
#    - FRONTEND_URL (Base URL of your frontend app for email links)

# 5. Set up the Database
# Ensure PostgreSQL server is running and the database/user exist
python manage.py migrate

# 6. Create a Superuser (Optional, for admin access)
python manage.py createsuperuser

# 7. Run the Development Server
python manage.py runserver
```

### 7.3. Running Tests
```bash
# Ensure test dependencies are installed (if separate requirements_test.txt)
# pip install -r requirements_test.txt

# Run the test suite
python manage.py test
```

## 8. Usage Examples

### 8.1. `curl` Examples

**Signup:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
        "email": "test@example.com",
        "password": "ComplexP@ssword123"
      }'
```

**Login:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
        "email": "test@example.com",
        "password": "ComplexP@ssword123"
      }'
# (Save the returned access and refresh tokens)
```

**Refresh Token:**
```bash
REFRESH_TOKEN="your_saved_refresh_token"
curl -X POST http://localhost:8000/api/v1/auth/token/refresh \
  -H "Content-Type: application/json" \
  -d '{ "refresh": "'"$REFRESH_TOKEN"'" }'
```

**Access Protected Route:**
```bash
ACCESS_TOKEN="your_saved_access_token"
curl -X GET http://localhost:8000/api/v1/users/me \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### 8.2. Client-Side JavaScript (`fetch`) Example

```javascript
// --- Login ---
async function loginUser(email, password) {
  try {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    // Securely store tokens (e.g., access in memory, refresh via HttpOnly cookie set by server)
    console.log('Login successful:', data);
    localStorage.setItem('accessToken', data.access); // Example: Storing access token
    // Note: Refresh token ideally handled by HttpOnly cookie
    return data;

  } catch (error) {
    console.error('Login failed:', error);
    // Handle login error (e.g., display message to user)
  }
}

// --- Fetch User Profile ---
async function fetchUserProfile() {
  const accessToken = localStorage.getItem('accessToken'); // Retrieve stored token

  if (!accessToken) {
    console.error('No access token found.');
    // Handle case where user is not logged in
    return;
  }

  try {
    const response = await fetch('/api/v1/users/me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (response.status === 401) {
       console.error('Unauthorized or token expired.');
       // Attempt to refresh token here or prompt login
       // Example: await refreshToken(); fetchUserProfile();
       return;
    }

    if (!response.ok) {
       const errorData = await response.json();
       throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    const userData = await response.json();
    console.log('User profile:', userData);
    return userData;

  } catch (error) {
    console.error('Failed to fetch user profile:', error);
    // Handle error
  }
}

// --- Refresh Token (Conceptual - Assumes refresh token is in HttpOnly cookie) ---
async function refreshToken() {
   try {
      // The refresh token is sent automatically if stored in an HttpOnly cookie
      const response = await fetch('/api/v1/auth/token/refresh', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         // No body needed if refresh token is in cookie, otherwise send it:
         // body: JSON.stringify({ refresh: getRefreshTokenFromSomewhere() })
      });

      if (!response.ok) {
         throw new Error('Failed to refresh token');
      }
      const data = await response.json();
      localStorage.setItem('accessToken', data.access); // Store new access token
      console.log('Token refreshed successfully.');
      return true;
   } catch (error) {
      console.error('Token refresh failed:', error);
      // Handle refresh failure (e.g., redirect to login)
      // clearTokens(); // Function to clear stored tokens/cookies
      // window.location.href = '/login';
      return false;
   }
}

```

## 9. Error Handling Strategy

*   Use standard HTTP status codes to indicate the outcome of API requests (e.g., `200 OK`, `201 Created`, `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `429 Too Many Requests`, `500 Internal Server Error`).
*   Return JSON error responses with a consistent structure:
    ```json
    // Example 400 Bad Request
    {
      "error": "VALIDATION_ERROR", // Machine-readable error code
      "message": "Invalid input provided.", // Human-readable summary
      "details": { // Optional: Field-specific errors
        "email": ["Enter a valid email address."],
        "password": ["Password does not meet complexity requirements."]
      }
    }

    // Example 401 Unauthorized
    {
        "error": "AUTHENTICATION_FAILED",
        "message": "Invalid credentials or email not verified."
    }
    ```
*   Avoid revealing sensitive information in error messages (e.g., stack traces in production).

## 10. Deployment Considerations

*   **Environment Variables:** Never hardcode secrets. Use environment variables or a secrets management system.
*   **HTTPS:** Configure a reverse proxy (like Nginx or Caddy) to handle HTTPS termination.
*   **Database:** Use a managed database service for production. Ensure backups are configured.
*   **WSGI Server:** Use a production-grade WSGI server (like Gunicorn or uWSGI) behind the reverse proxy.
*   **Static Files:** Configure the reverse proxy to serve static files efficiently.
*   **Logging:** Implement structured logging and aggregate logs for monitoring and debugging.
*   **Monitoring:** Set up monitoring for application performance, error rates, and system resources.
*   **Security Hardening:** Apply OS and server hardening techniques. Keep systems patched.

## 11. Contributing

*(Placeholder: Add guidelines here if the project becomes open source, e.g., code style, pull request process, issue reporting.)*

## 12. License

*(Placeholder: Specify the project's license, e.g., MIT, Apache 2.0.)*

