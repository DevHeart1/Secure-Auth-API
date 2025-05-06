# Secure Auth API - Backend Workflow and Step-by-Step Guide

This document outlines the primary system flows for the Secure Auth API, focusing on backend interactions and expected API client behavior.

## 1. User Registration and Email Verification Flow

This flow describes how a new user account is created and prepared for email verification via API calls.

1.  **API Client Action:** Client sends user details (email, password, optional name) in a request to the `POST /api/v1/auth/signup` endpoint.
2.  **API Action (Signup):**
    *   Validates the submitted data (email format, password complexity).
    *   Checks if the email already exists in the database.
    *   If validation passes and email is unique, creates a new user record with `is_verified` set to `false`.
    *   Hashes the provided password using `bcrypt`.
    *   Generates a unique, time-limited email verification token.
    *   Stores the token, associating it with the new user account.
    *   Triggers an asynchronous task (e.g., using Celery) to send a verification email to the user's address. The email contains a link with the token (e.g., `https://yourdomain.com/verify?token=<verification_token>` - *Note: The exact link structure depends on how verification will eventually be handled*).
    *   Returns a `201 Created` response to the client, indicating success.
3.  **User Action:** User receives the verification email and extracts the verification token (manually or via a future frontend).
4.  **API Client Action:** Client sends the extracted token in a request to the `POST /api/v1/auth/verify-email` endpoint.
5.  **API Action (Verify Email):**
    *   Receives the verification token.
    *   Validates the token: checks if it exists, hasn't expired, and matches a user.
    *   If the token is valid:
        *   Updates the corresponding user record, setting `is_verified` to `true`.
        *   Invalidates or deletes the used verification token to prevent reuse.
        *   Returns a `200 OK` success response to the client.
    *   If the token is invalid or expired, returns an appropriate error (`400 Bad Request` or `404 Not Found`).
6.  **Outcome:** The user's email is now verified via API interaction. The account is ready for login.

## 2. Standard Login Flow (Email/Password)

This flow describes how a verified user authenticates via the API.

1.  **API Client Action:** Client sends the user's email and password in a request to the `POST /api/v1/auth/login` endpoint.
2.  **API Action (Login):**
    *   Receives email and password.
    *   Validates the input.
    *   Finds the user by email.
    *   If user exists, compares the provided password with the stored hash using `bcrypt`.
    *   Checks if the user's `is_verified` status is `true`.
    *   If credentials are correct AND the email is verified:
        *   Generates a short-lived JWT Access Token.
        *   Generates a longer-lived JWT Refresh Token.
        *   Returns a `200 OK` response containing both the `access` and `refresh` tokens in the JSON body.
    *   If credentials are incorrect, email is not verified, or user doesn't exist, returns a `401 Unauthorized` error.
    *   If rate limits are exceeded, returns `429 Too Many Requests`.
3.  **API Client Action:**
    *   Receives the tokens upon successful login.
    *   Stores the tokens securely for subsequent requests.
4.  **Outcome:** The API client has received authentication tokens and can now make authenticated requests.

## 3. Accessing Protected Resources Flow

This flow describes how an authenticated API client accesses protected endpoints.

1.  **API Client Action:** Client needs to access a protected endpoint (e.g., `GET /api/v1/users/me`).
2.  **API Client Action:** Retrieves the stored Access Token.
3.  **API Client Action:** Makes the API request, including the Access Token in the `Authorization` header: `Authorization: Bearer <access_token>`.
4.  **API Action (Middleware/Decorator):**
    *   Extracts the token from the `Authorization` header.
    *   Validates the token's signature and expiration time.
    *   If the token is valid, identifies the user associated with the token.
    *   Allows the request to proceed to the target endpoint controller/view.
    *   If the token is invalid or expired, rejects the request with a `401 Unauthorized` error.
5.  **API Action (Endpoint Logic):** The endpoint logic executes, performs its function (e.g., fetching user data), and returns the appropriate response (`200 OK` with data).
6.  **API Client Action:** Receives the response from the API.

## 4. Token Refresh Flow

This flow describes how the API client obtains a new Access Token using the Refresh Token.

1.  **API Client Action:** Attempts to access a protected resource, but the API returns a `401 Unauthorized` error, indicating the Access Token has expired.
2.  **API Client Action:** Retrieves the stored Refresh Token.
3.  **API Client Action:** Sends the Refresh Token in a request to the `POST /api/v1/auth/token/refresh` endpoint.
4.  **API Action (Token Refresh):**
    *   Receives the Refresh Token.
    *   Validates the Refresh Token (checks if it's valid, not expired, and not blacklisted).
    *   If the Refresh Token is valid:
        *   Generates a *new* short-lived JWT Access Token for the associated user.
        *   (Optional but recommended: Implement refresh token rotation - issue a new refresh token as well and invalidate the old one).
        *   Returns a `200 OK` response containing the new `access` token (and potentially the new refresh token) in the JSON body.
    *   If the Refresh Token is invalid or expired, returns a `401 Unauthorized` error.
5.  **API Client Action:**
    *   Receives the new Access Token (and potentially Refresh Token).
    *   Stores the new token(s) securely, replacing the old one(s).
    *   Retries the original API request (from step 1) using the new Access Token.
6.  **Outcome:** The API client has refreshed its Access Token and can continue accessing protected resources.

## 5. Password Reset Flow

This flow describes how a password reset is initiated and confirmed via the API.

1.  **API Client Action:** Client sends the user's email address in a request to the `POST /api/v1/auth/password/reset` endpoint.
2.  **API Action (Initiate Reset):**
    *   Receives the email address.
    *   Checks if an active, verified user exists with that email.
    *   If a user exists (or even if not, to prevent enumeration), generates a unique, time-limited password reset token.
    *   Stores the token, associating it with the user account.
    *   Triggers an asynchronous task to send a password reset email to the user. The email contains the reset token or a link containing it (e.g., `https://yourdomain.com/reset?token=<reset_token>` - *Note: Link structure depends on eventual handling*).
    *   Returns a generic `200 OK` success response (even if the email wasn't found).
3.  **User Action:** User receives the password reset email and extracts the reset token.
4.  **API Client Action:** Client sends the `token` and the `new_password` in a request to the `POST /api/v1/auth/password/reset/confirm` endpoint.
5.  **API Action (Confirm Reset):**
    *   Receives the token and new password.
    *   Validates the token (checks existence, expiry, association).
    *   Validates the new password against complexity rules.
    *   If the token and password are valid:
        *   Finds the associated user.
        *   Hashes the new password.
        *   Updates the user's password hash in the database.
        *   Invalidates or deletes the used password reset token.
        *   (Optional: Invalidate user's active refresh tokens).
        *   Returns a `200 OK` success response.
    *   If the token is invalid/expired or the password is weak, returns a `400 Bad Request` error.
6.  **Outcome:** The user's password has been successfully reset via API interaction.

## 6. OAuth2 Social Login Flow (Backend Perspective - Example: Google)

This flow describes the backend steps involved in handling an OAuth2 login, assuming the initial redirect to the provider and the final callback handling occur via API endpoints.

1.  **API Client Action (Initiation):** Client makes a request to the API's initiation endpoint, e.g., `GET /api/v1/auth/google`.
2.  **API Action (Initiate OAuth):**
    *   Constructs the Google OAuth2 authorization URL, including client ID, redirect URI (pointing back to the API's callback), requested scopes, and a unique `state` parameter.
    *   Returns a `302 Found` redirect response, with the `Location` header set to Google's authentication URL.
3.  **External Interaction:** The entity initiating the request (e.g., a user via a browser, or a test script) follows the redirect to Google, authenticates, and grants permissions.
4.  **Google Action:** Redirects back to the API's configured callback URL (e.g., `GET /api/v1/auth/google/callback`), including an authorization `code` and the original `state` parameter.
5.  **API Action (Callback Handling):**
    *   Receives the request at the callback endpoint.
    *   Validates the received `state` parameter.
    *   Makes a secure, server-to-server request to Google's token endpoint, exchanging the `code` for Google's access/ID tokens.
    *   Validates the ID token from Google.
    *   Extracts user information (email, name, etc.).
    *   Checks if a user account exists locally with the verified email address.
        *   **If User Exists:** Log the user in.
        *   **If User Doesn't Exist:** Create a new user account (marked as verified).
    *   Generates the API's own JWT Access Token and Refresh Token for the user.
    *   Returns a `200 OK` response containing the API's `access` and `refresh` tokens in the JSON body. (Instead of redirecting a browser, the API directly provides tokens to the API client that handled the callback).
6.  **API Client Action:**
    *   Receives the `200 OK` response with the API tokens.
    *   Stores the tokens securely.
7.  **Outcome:** The API client has successfully authenticated the user via Google OAuth2 and obtained API tokens.

Next Steps
To complete the implementation of our secure authentication API, consider the following next steps:

Production Deployment:

Set up a proper PostgreSQL database
Configure Redis for Celery task queue
Set up proper email service credentials
Secure environment variables for production
Testing:

Unit tests for models and authentication flows
Integration tests for API endpoints
Documentation:

API documentation using tools like Swagger/OpenAPI
Monitoring:

Add logging for authentication attempts and security events
Set up monitoring for failed logins and potential security issues
Would you like me to explain any specific aspect of the implementation in more detail?