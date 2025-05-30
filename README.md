# Firebase JWT Authentication Demo

This Spring Boot application demonstrates how to authenticate Firebase ID tokens from multiple Firebase projects using JJWT library.

## Features

- JWT authentication for multiple Firebase projects
- Google public key caching with Caffeine
- Spring Security integration
- RESTful API endpoints requiring authentication

## Configuration

Update `src/main/resources/application.properties` with your Firebase project IDs:

```properties
firebase.project-ids=your-project-a-id,your-project-b-id
```

## API Endpoints

### Authenticated Endpoints
- `GET /api/user/me` - Get current authenticated user ID
- `GET /api/user/me/principal` - Get user via Principal interface  
- `GET /api/user/profile` - Get mock user profile data

### Public Endpoints
- `GET /actuator/health` - Health check endpoint

## Usage

1. Start the application:
   ```bash
   ./gradlew bootRun
   ```

2. Make authenticated requests with Firebase ID token:
   ```bash
   curl -H "Authorization: Bearer <FIREBASE_ID_TOKEN>" \
        http://localhost:8080/api/user/me
   ```

## Dependencies

- Spring Boot 3.4.0
- Kotlin 2.1.20  
- JJWT 0.12.6
- Caffeine Cache 3.2.0

## Architecture

- **GooglePublicKeyService**: Fetches and caches Google's public keys for JWT signature verification
- **JwtAuthFilter**: Custom Spring Security filter that validates Firebase ID tokens
- **SecurityConfig**: Spring Security configuration with JWT authentication
- **UserController**: Sample REST endpoints requiring authentication

The implementation validates JWT signature, issuer, audience, and expiration claims against configured Firebase project IDs.