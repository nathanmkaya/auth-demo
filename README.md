
# Firebase JWT Authentication Demo

This Spring Boot application demonstrates how to authenticate Firebase ID tokens from multiple Firebase projects using the **Auth0 Java JWT library**.

## Features

- JWT authentication for multiple Firebase projects using **Auth0 Java JWT**.
- Google public key fetching and caching handled by **Auth0's `JwkProvider`**.
- Spring Security integration.
- RESTful API endpoints requiring authentication.
- Validation of Firebase-specific claims (`sub`, `auth_time`).

## Configuration

Update `src/main/resources/application.properties` with your Firebase project IDs:

```properties
firebase.project-ids=your-project-a-id,your-project-b-id
```

And ensure the `google.jwk-set-uri` is set to the correct Firebase JWK endpoint:
```properties
google.jwk-set-uri=https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com
```

## API Endpoints

### Authenticated Endpoints
- `GET /api/user/me` - Get current authenticated user ID.
- `GET /api/user/me/principal` - Get user via Principal interface.
- `GET /api/user/profile` - Get mock user profile data.

### Public Endpoints
- `GET /actuator/health` - Health check endpoint.

## Usage

1.  Start the application:
    ```bash
    ./gradlew bootRun
    ```

2.  Obtain a Firebase ID token from your client application.

3.  Make authenticated requests with the Firebase ID token in the Authorization header:
    ```bash
    curl -H "Authorization: Bearer <YOUR_FIREBASE_ID_TOKEN>" \
         http://localhost:8080/api/user/me
    ```

## Dependencies

Key dependencies include:

- Spring Boot 3.4.0 (or your current version)
- Kotlin 2.1.20 (or your current version)
- **Auth0 Java JWT (`com.auth0:java-jwt:4.4.0`)**
- **Auth0 JWKS RSA (`com.auth0:jwks-rsa:0.22.1`)**
- Spring Boot Starter Security, Web, WebFlux, Actuator
- (Caffeine Cache is still listed but might be optional if no other part of the application uses Spring's `@Cacheable` with Caffeine, as JWK caching is now internal to Auth0's `JwkProvider`)

## Architecture

- **`GooglePublicKeyService`**: Uses Auth0's `JwkProvider` to fetch, cache, and provide Google's RSA public keys necessary for JWT signature verification. The `JwkProvider` handles caching and rate-limiting internally.
- **`JwtAuthFilter`**: A custom Spring Security filter that intercepts requests, extracts the Firebase ID token, and validates it using the `java-jwt` library. It verifies the token's signature, standard claims (expiration, issuer, audience), and Firebase-specific claims (`sub`, `auth_time`).
- **`SecurityConfig`**: Configures Spring Security to use the `JwtAuthFilter` and defines authorization rules.
- **`FirebaseProperties` & `GoogleJwkProperties`**: Type-safe configuration classes for Firebase and Google JWK settings.
- **`UserController`**: Contains sample REST endpoints that require successful JWT authentication.

The implementation validates the JWT signature, issuer (against a list of allowed Firebase project IDs), audience (against a list of allowed Firebase project IDs), expiration, and other Firebase-specific claims.