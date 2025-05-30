# Authenticating Multiple Firebase Apps (from Different Projects) with JJWT and Kotlin/Spring Boot

This document outlines how to configure a single backend service (Kotlin/Spring Boot) to authenticate requests from different client applications using Firebase Authentication **from separate Firebase projects**. This approach uses the **`jjwt` library** for parsing and validating Firebase ID Tokens via a custom Spring Security filter, offering fine-grained control over the validation process.

## 1. Understanding Firebase ID Tokens

When a user successfully signs in using Firebase Authentication on a client application, Firebase issues a JSON Web Token (JWT) called an ID Token. This token contains information about the signed-in user and is cryptographically signed by Google. Key claims within the token include:

* `iss` (Issuer): Identifies the principal that issued the JWT. For Firebase tokens, it's `https://securetoken.google.com/<FIREBASE_PROJECT_ID_OF_ISSUING_APP>`.
* `aud` (Audience): Identifies the recipients that the JWT is intended for. For Firebase ID tokens, this is **the Firebase Project ID associated with the client app that requested the token**.
* `sub` (Subject): The user's unique Firebase UID (unique within the context of its Firebase project).
* `email`, `name`, `picture`: Basic profile information (if available).
* `auth_time`: The time the user authenticated.
* `iat` (Issued At): The time the JWT was issued.
* `exp` (Expiration Time): The time after which the JWT expires.

## 2. The Authentication Flow

1.  **Client Authentication:** User signs into App 1 (Project A) or App 2 (Project B).
2.  **Token Retrieval:** Client app gets the Firebase ID Token.
3.  **API Request:** Client sends the token in the `Authorization: Bearer <TOKEN>` header.
4.  **Backend Verification (Custom Filter):**
    * The custom Spring Security filter intercepts the request.
    * It extracts the Bearer token.
    * It uses `jjwt` to parse and validate the token's signature against Google's public keys.
    * It validates claims (`exp`, `iss`, `aud`) against allowed project IDs using `jjwt`'s built-in checks.
5.  **Security Context Update:** If valid, the filter creates an `Authentication` object and sets it in the `SecurityContextHolder`.
6.  **Access Control:** Spring Security uses the populated `SecurityContext` to authorize the request. If the token is invalid or missing, the filter chain proceeds without authentication, likely resulting in a 401/403 response based on security rules.

## 3. Backend Verification Strategy (Multiple Projects with JJWT)

The custom filter performs these checks using `jjwt`:

1.  **Token Extraction:** Get the token from the `Authorization` header.
2.  **Signature Verification:**
    * Fetch Google's public keys (JWKs) from `https://www.googleapis.com/robot/v1/keys`. **Caching these keys is crucial for performance.**
    * Parse the token header to find the `kid` (Key ID).
    * Find the matching public key from the fetched JWKs based on the `kid`.
    * Use `jjwt`'s `Jwts.parserBuilder().setSigningKeyResolver(...)` to verify the signature using the correct key.
3.  **Claims Validation:** Use `jjwt`'s parser methods (`requireIssuer`, `requireAudience`, `requireExpiration`, etc.) to validate:
    * **Expiration (`exp`):** Ensure the token is not expired.
    * **Issuer (`iss`):** Check if the issuer is one of the expected `https://securetoken.google.com/<ALLOWED_PROJECT_ID>` values.
    * **Audience (`aud`):** Check if the audience claim matches one of the `allowedFirebaseProjectIds`.

## 4. Implementation with Kotlin, Spring Boot, and JJWT

**Dependencies (build.gradle.kts):**

```kotlin
dependencies {
    implementation("org.springframework.boot:spring-boot-starter-security")
    // JJWT API and Implementation
    implementation("io.jsonwebtoken:jjwt-api:0.12.5") // Or latest version
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.5")
    // JJWT Jackson support for JSON parsing (or use Gson: jjwt-gson)
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.5")

    // For fetching JWKs (using Spring's RestTemplate or WebClient)
    implementation("org.springframework.boot:spring-boot-starter-webflux") // For WebClient (recommended)
    // Or implementation("org.springframework.boot:spring-boot-starter-web") // For RestTemplate

    // Optional: Caching for JWKs
    implementation("org.springframework.boot:spring-boot-starter-cache")
    implementation("com.github.ben-manes.caffeine:caffeine") // Example cache implementation
}
```

**Configuration (application.properties):**

```properties
# List your allowed Firebase Project IDs, separated by commas
firebase.project-ids=your-project-a-id,your-project-b-id

# Google JWK Set URI
google.jwk-set-uri=[https://www.googleapis.com/robot/v1/keys](https://www.googleapis.com/robot/v1/keys)

# Optional: Cache configuration
spring.cache.cache-names=googleJwkSet
spring.cache.caffeine.spec=maximumSize=1,expireAfterWrite=24h # Cache JWKs for 24 hours
```

**Google Public Key Service (GooglePublicKeyService.kt):**

A service to fetch and cache Google's public keys.

```kotlin
package com.yourcompany.auth

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.security.Jwk
// import io.jsonwebtoken.security.JwkSet // JwkSet might not be directly used depending on parsing method
import io.jsonwebtoken.security.Jwks
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.cache.annotation.Cacheable
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import java.security.Key
// import java.util.concurrent.ConcurrentHashMap // Removed as using Spring Cache

@Service
class GooglePublicKeyService(private val webClientBuilder: WebClient.Builder) {

    private val log = LoggerFactory.getLogger(GooglePublicKeyService::class.java)

    @Value("\${google.jwk-set-uri}")
    private lateinit var jwkSetUri: String

    // Use Spring Cache Abstraction for better caching
    @Cacheable("googleJwkSet") // Matches cache name in application.properties
    fun fetchJwkSet(): Map<String, Jwk<*>> {
        log.info("Fetching Google JWK Set from {}", jwkSetUri)
        try {
            val responseBody = webClientBuilder.build()
                .get()
                .uri(jwkSetUri)
                .retrieve()
                .bodyToMono<String>() // Fetch as String first for parsing flexibility
                .block() // Blocking call - consider async if needed in other contexts

            if (responseBody == null) {
                log.error("Received empty response body from JWK Set URI: {}", jwkSetUri)
                throw RuntimeException("Failed to fetch JWK Set: Empty response")
            }

            // Manually parse the top-level structure using Jackson
            val objectMapper = ObjectMapper()
            val jwkMap: Map<String, List<Map<String, Any>>> = objectMapper.readValue(responseBody, object : TypeReference<Map<String, List<Map<String, Any>>>>() {})
            val keysList = jwkMap["keys"] ?: throw RuntimeException("JWK Set JSON does not contain 'keys' array")

            // Parse each key map within the 'keys' array using JJWT's Jwks parser
            val parsedJwks = keysList.mapNotNull { keyMap -> // Use mapNotNull to filter out nulls directly
                 try {
                     Jwks.parser().build(keyMap)
                 } catch (e: Exception) {
                     log.warn("Failed to parse individual JWK: {}. Skipping.", keyMap, e)
                     null // Return null for unparseable keys
                 }
            }

            if (parsedJwks.isEmpty()) {
                 throw RuntimeException("No valid JWKs could be parsed from the fetched set at $jwkSetUri")
            }

            // Create a map from kid -> Jwk for easy lookup
            return parsedJwks.associateBy {
                 it.id ?: throw IllegalArgumentException("Parsed JWK is missing 'kid'. Key map: $it") // Ensure kid exists
            }

        } catch (e: Exception) {
            log.error("Failed to fetch or parse Google JWK Set from {}: {}", jwkSetUri, e.message, e)
            // Rethrow a more specific exception or handle as per policy
            throw RuntimeException("Failed to obtain Google public keys from $jwkSetUri", e)
        }
    }

    fun getPublicKey(kid: String): Key {
        val jwkSetMap = fetchJwkSet() // This will hit the cache if populated
        val jwk = jwkSetMap[kid] ?: throw UnsupportedJwtException("JWT Key ID '$kid' not found in cached/fetched JWK Set from $jwkSetUri")

        // Ensure the parsed Jwk actually contains a Key object
        return jwk.key ?: throw UnsupportedJwtException("JWK '$kid' from $jwkSetUri did not produce a usable Key object.")
        // No need to check type `is Key` as jwk.key returns Key or null
    }
}
```

**Custom JWT Authentication Filter (JwtAuthFilter.kt):**

```kotlin
package com.yourcompany.auth

import io.jsonwebtoken.*
import io.jsonwebtoken.security.SecurityException // For signature/key issues
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.security.Key
import java.util.*

@Component
class JwtAuthFilter(
    private val googlePublicKeyService: GooglePublicKeyService
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(JwtAuthFilter::class.java)

    @Value("\${firebase.project-ids}")
    private lateinit var allowedFirebaseProjectIds: List<String>

    // Lazily initialize derived properties after dependency injection
    private val allowedIssuers: Set<String> by lazy {
        allowedFirebaseProjectIds.map { "[https://securetoken.google.com/$it](https://securetoken.google.com/$it)" }.toSet()
    }
    private val allowedAudiences: Set<String> by lazy {
        allowedFirebaseProjectIds.toSet()
    }

    // Create the SigningKeyResolver using the GooglePublicKeyService
    // Using SigningKeyResolverAdapter for compatibility with modern JJWT
    private val signingKeyResolver = object : SigningKeyResolverAdapter() {
        override fun resolveSigningKey(header: JwsHeader<*>?): Key {
            val keyId = header?.keyId ?: throw UnsupportedJwtException("JWT header does not contain 'kid' claim.")
            try {
                // Delegate to the service to get the key (handles caching)
                return googlePublicKeyService.getPublicKey(keyId)
            } catch (e: Exception) {
                // Log specific error from publicKeyService
                log.error("Failed to resolve signing key for kid '{}': {}", keyId, e.message)
                // Re-throw as a type JJWT understands for parsing failure
                throw SecurityException("Could not resolve signing key for kid '$keyId'", e)
            }
        }
    }


    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            val token = extractToken(request)
            if (token != null) {
                val claims = validateToken(token)
                if (claims != null) {
                    setupAuthentication(request, claims)
                    log.debug("JWT Authentication successful for user: {}", claims.subject)
                } else {
                    log.debug("JWT Token validation failed or token was invalid.")
                    // Ensure context is clear if validation fails
                     SecurityContextHolder.clearContext()
                }
            } else {
                 log.trace("No JWT token found in Authorization header.")
            }
        } catch (e: Exception) {
            // Catch unexpected errors during filter processing (e.g., context setup)
            log.error("Error processing JWT filter: {}", e.message, e)
            SecurityContextHolder.clearContext() // Ensure context is cleared on any filter error
            // Let Spring Security's ExceptionTranslationFilter handle the response
        }

        // Proceed with the filter chain. If authentication wasn't set,
        // subsequent security checks (like authorizeHttpRequests) will deny access.
        filterChain.doFilter(request, response)
    }

    private fun extractToken(request: HttpServletRequest): String? {
        val header = request.getHeader("Authorization")
        return if (header != null && header.startsWith("Bearer ")) {
            header.substring(7)
        } else {
            null
        }
    }

    private fun validateToken(token: String): Claims<*>? {
        try {
            // Build the parser with all requirements
            val parser: JwtParser = Jwts.parser()
                .setSigningKeyResolver(signingKeyResolver) // Verify signature using Google's keys
                .requireIssuerIn(allowedIssuers)          // Verify issuer is one of the allowed ones
                .requireAudienceIn(allowedAudiences)      // Verify audience is one of the allowed ones
                // Expiration (exp) and Not Before (nbf) are checked by default
                .build()

            // Parse the token. This performs all validations defined above.
            val jws: Jws<Claims<*>> = parser.parseSignedClaims(token)

            // If parsing succeeds, the token is valid according to the rules.
            return jws.payload // Return the claims payload

        } catch (ex: MissingClaimException) {
            log.warn("JWT validation failed - Missing required claim [{}]: {}", ex.header, ex.message)
        } catch (ex: IncorrectClaimException) {
             log.warn("JWT validation failed - Incorrect claim [{}]: {}", ex.header, ex.message)
        } catch (ex: SecurityException) { // Includes SignatureException
            log.warn("Invalid JWT signature or key issue: {}", ex.message)
        } catch (ex: MalformedJwtException) {
            log.warn("Invalid JWT token format: {}", ex.message)
        } catch (ex: ExpiredJwtException) {
            log.warn("Expired JWT token used: {}", ex.message)
        } catch (ex: UnsupportedJwtException) {
            log.warn("Unsupported JWT token type or structure: {}", ex.message)
        } catch (ex: IllegalArgumentException) {
            // Catches issues like empty token string or null arguments passed to JJWT
            log.warn("JWT processing failed due to invalid argument: {}", ex.message)
        } catch (e: Exception) {
            // Catch-all for other potential JJWT or underlying issues during validation
            log.error("Unexpected error during JWT validation: {}", e.message, e)
        }
        // Return null if any validation exception occurred
        return null
    }

     private fun setupAuthentication(request: HttpServletRequest, claims: Claims<*>) {
        val userId = claims.subject
        if (userId.isNullOrBlank()) { // Check if subject is present and not empty
             log.warn("JWT subject (user ID) is missing or blank. Cannot set up authentication.")
             return // Do not proceed if userId is invalid
        }

        // Define authorities. In a real app, you might look these up based on userId.
        // For Firebase tokens, typically start with a base role.
        val authorities = listOf(SimpleGrantedAuthority("ROLE_USER")) // Default role

        // Create the Authentication token for Spring Security context
        val authentication = UsernamePasswordAuthenticationToken(
            userId, // Principal: The authenticated user identifier
            null,   // Credentials: Null for token-based auth after validation
            authorities // Authorities/Roles granted to the user
        )

        // Set optional details (like remote address) from the request
        authentication.details = WebAuthenticationDetailsSource().buildDetails(request)

        // Store the Authentication object in the SecurityContextHolder
        // This makes it available for authorization checks later in the filter chain
        SecurityContextHolder.getContext().authentication = authentication
    }
}
```

**Security Configuration (SecurityConfig.kt):**

Now, configure Spring Security to use the custom filter.

```kotlin
package com.yourcompany.config // Or your config package

import com.yourcompany.auth.JwtAuthFilter // Import your custom filter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
// import org.springframework.cache.annotation.EnableCaching // Enable caching if used
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.reactive.function.client.WebClient

@Configuration
@EnableWebSecurity
// @EnableCaching // Uncomment if using @Cacheable in GooglePublicKeyService
class SecurityConfig(private val jwtAuthFilter: JwtAuthFilter) { // Inject the custom filter

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            // Disable CSRF protection - common for stateless APIs
            .csrf { csrf -> csrf.disable() }
            // Configure session management to be stateless - no sessions created
            .sessionManagement { session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            }
            // Define authorization rules
            .authorizeHttpRequests { authorize ->
                authorize
                    // Example: Allow access to public endpoints without authentication
                    // .requestMatchers("/public/**", "/actuator/health").permitAll()
                    // Require authentication for all other requests
                    .anyRequest().authenticated()
            }
            // Add the custom JWT authentication filter before the standard form login filter
            // Ensures JWT check happens for relevant requests.
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter::class.java)

        return http.build()
    }

     // Provide a WebClient.Builder bean for dependency injection
     // (Used by GooglePublicKeyService)
     @Bean
     fun webClientBuilder(): WebClient.Builder {
         return WebClient.builder()
     }
}
```

**Controller (UserController.kt):**

Accessing the authenticated user (principal).

```kotlin
package com.yourcompany.controller // Or your controller package

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal // Can also use standard Principal

@RestController
@RequestMapping("/api/user")
class UserController {

    @GetMapping("/me")
    // Use @AuthenticationPrincipal to inject the principal (userId String)
    // set by JwtAuthFilter into the SecurityContext
    fun getCurrentUser(@AuthenticationPrincipal userId: String): Map<String, Any> {
        // The 'userId' parameter directly holds the Firebase UID (subject claim)
        // which was set as the principal in the Authentication object.

        // You can now use this userId to fetch user-specific data from your database
        // or perform actions on behalf of this authenticated user.

        return mapOf(
            "authenticatedUserId" to userId
            // Add other user details fetched from your own services if needed
        )
    }

     // Alternative using java.security.Principal
     @GetMapping("/me/principal")
     fun getCurrentUserPrincipal(principal: Principal): Map<String, Any> {
         // principal.name will contain the userId set in the Authentication object
         return mapOf(
             "authenticatedUserIdFromPrincipal" to principal.name
         )
     }
}
```

## Summary

This approach uses a custom `JwtAuthFilter` powered by the `jjwt` library to validate Firebase ID tokens from multiple projects. It involves fetching and caching Google's public keys, using `jjwt`'s `SigningKeyResolver` for signature verification, and leveraging its built-in methods for validating `iss`, `aud`, and `exp` claims against your allowed Firebase Project IDs. This provides granular control but requires more manual setup compared to the Spring Security OAuth2 Resource Server module. Remember to handle key fetching/caching robustly and manage dependencies correctly.
