# Chirpy API

A simple social media API built with Go that allows users to post short messages called "chirps".

## API Endpoints

### Health & Metrics
- **GET /api/healthz** - Health check endpoint, returns "OK" status
- **GET /admin/metrics** - Admin page showing visitor count statistics  
- **POST /admin/reset** - Reset database and metrics (development only)

### User Management
- **POST /api/users** - Create a new user account
- **PUT /api/users** - Update user email and password (requires authentication)
- **POST /api/login** - User login, returns access and refresh tokens
- **POST /api/refresh** - Refresh access token using refresh token
- **POST /api/revoke** - Revoke a refresh token

### Chirps (Posts)
- **POST /api/chirps** - Create a new chirp (requires authentication)
- **GET /api/chirps** - Get all chirps with optional query parameters:
  - `author_id`: Filter by user ID
  - `sort`: Sort direction ("asc" or "desc")
- **GET /api/chirps/{chirpID}** - Get a specific chirp by ID
- **DELETE /api/chirps/{chirpID}** - Delete a chirp (requires authentication, owner only)

### Webhooks
- **POST /api/polka/webhooks** - Polka webhook for user upgrades (requires API key)

### Static Files
- **/app/*** - Serves static files with visitor tracking

## Authentication

The API uses JWT tokens for authentication. Include the token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

Refresh tokens are also supported for obtaining new access tokens without re-authentication.

## Features

- User registration and authentication
- Password hashing with bcrypt
- JWT-based authentication with refresh tokens
- Chirp creation with profanity filtering
- Chirp sorting and filtering
- User upgrade webhook integration
- Static file serving with metrics tracking