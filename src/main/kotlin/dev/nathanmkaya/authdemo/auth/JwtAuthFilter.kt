package dev.nathanmkaya.authdemo.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.*
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.interfaces.RSAKeyProvider
import dev.nathanmkaya.authdemo.config.FirebaseProperties
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

/**
 * JWT authentication filter that validates Firebase ID tokens on incoming requests.
 * 
 * This filter extracts JWT tokens from the Authorization header, validates them using
 * Firebase's official JWK endpoint, and sets up Spring Security authentication context 
 * for valid tokens. Implementation follows Firebase's official documentation for 
 * third-party JWT library verification.
 * 
 * Validates all required claims per Firebase documentation:
 * - Header: alg=RS256, kid matches Firebase keys
 * - Payload: exp, iat, aud, iss, sub, auth_time
 * - Supports multiple Firebase project IDs
 */
@Component
class JwtAuthFilter(
    private val googlePublicKeyService: GooglePublicKeyService,
    private val firebaseProperties: FirebaseProperties
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(JwtAuthFilter::class.java)

    private val allowedIssuers: Set<String> by lazy {
        firebaseProperties.projectIds.map { "https://securetoken.google.com/$it" }.toSet()
    }
    private val allowedAudiences: Set<String> by lazy {
        firebaseProperties.projectIds.toSet()
    }

    /**
     * RSA Key Provider for Auth0 JWT library.
     * Provides public keys for JWT verification using Google's JWK endpoint.
     */
    private val keyProvider = object : RSAKeyProvider {
        override fun getPublicKeyById(keyId: String): RSAPublicKey? {
            return try {
                googlePublicKeyService.getPublicKey(keyId)
            } catch (e: Exception) {
                log.error("Failed to get public key for kid '{}': {}", keyId, e.message)
                null
            }
        }

        override fun getPrivateKey(): RSAPrivateKey? = null
        override fun getPrivateKeyId(): String? = null
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            val token = extractToken(request)
            if (token != null) {
                val decodedJWT = validateToken(token)
                if (decodedJWT != null) {
                    setupAuthentication(request, decodedJWT)
                    log.debug("JWT Authentication successful for userId: {}, issuer: {}", 
                        decodedJWT.subject, decodedJWT.issuer)
                } else {
                    log.debug("JWT Token validation failed for request to: {}", request.requestURI)
                    SecurityContextHolder.clearContext()
                }
            } else {
                log.trace("No JWT token found in Authorization header for request to: {}", request.requestURI)
            }
        } catch (e: Exception) {
            log.error("Error processing JWT filter: {}", e.message, e)
            SecurityContextHolder.clearContext()
        }

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

    private fun validateToken(token: String): DecodedJWT? {
        try {
            // Create RSA256 algorithm with our key provider
            val algorithm = Algorithm.RSA256(keyProvider)
            
            // Build JWT verifier with Auth0 library
            val verifier = JWT.require(algorithm)
                .acceptLeeway(1) // Allow 1 second of clock skew
                .build()

            // Verify and decode the token
            val decodedJWT = verifier.verify(token)
            
            // Firebase-specific validation
            validateMultipleIssuers(decodedJWT.issuer) ?: return null
            validateMultipleAudiences(decodedJWT.audience?.firstOrNull()) ?: return null
            validateFirebaseSpecificClaims(decodedJWT) ?: return null

            return decodedJWT

        } catch (ex: AlgorithmMismatchException) {
            log.warn("JWT validation failed - Algorithm mismatch: {}", ex.message)
        } catch (ex: SignatureVerificationException) {
            log.warn("JWT validation failed - Signature verification failed: {}", ex.message)
        } catch (ex: TokenExpiredException) {
            log.warn("JWT validation failed - Token expired: {}", ex.message)
        } catch (ex: InvalidClaimException) {
            log.warn("JWT validation failed - Invalid claim: {}", ex.message)
        } catch (ex: JWTDecodeException) {
            log.warn("JWT validation failed - Token decode error: {}", ex.message)
        } catch (ex: JWTVerificationException) {
            log.warn("JWT validation failed - Verification error: {}", ex.message)
        } catch (e: Exception) {
            log.error("Unexpected error during JWT validation: {}", e.message, e)
        }
        return null
    }

    /**
     * Validates the JWT issuer against multiple allowed Firebase project issuers.
     * 
     * @param issuer The issuer claim from the JWT
     * @return Unit if valid, null if invalid
     */
    private fun validateMultipleIssuers(issuer: String?): Unit? {
        return if (allowedIssuers.contains(issuer)) {
            Unit
        } else {
            log.warn("JWT validation failed - Invalid issuer: '{}'. Expected one of: [{}]", 
                issuer, allowedIssuers.joinToString(", "))
            null
        }
    }

    /**
     * Validates the JWT audience against multiple allowed Firebase project audiences.
     * 
     * @param audience The audience claim from the JWT
     * @return Unit if valid, null if invalid
     */
    private fun validateMultipleAudiences(audience: String?): Unit? {
        return if (allowedAudiences.contains(audience)) {
            Unit
        } else {
            log.warn("JWT validation failed - Invalid audience: '{}'. Expected one of: [{}]", 
                audience, allowedAudiences.joinToString(", "))
            null
        }
    }

    /**
     * Validates Firebase-specific JWT claims according to Firebase documentation.
     * 
     * @param decodedJWT The decoded JWT token
     * @return Unit if valid, null if invalid
     */
    private fun validateFirebaseSpecificClaims(decodedJWT: DecodedJWT): Unit? {
        // Validate subject (sub) is non-empty
        val subject = decodedJWT.subject
        if (subject.isNullOrBlank()) {
            log.warn("JWT validation failed - Subject (sub) claim is missing or empty")
            return null
        }

        // Validate auth_time exists and is in the past
        val authTimeClaim = decodedJWT.getClaim("auth_time")
        if (authTimeClaim.isNull) {
            log.warn("JWT validation failed - auth_time claim is missing")
            return null
        }

        try {
            val authTime = authTimeClaim.asDate()
            val now = java.util.Date()
            if (authTime.after(now)) {
                log.warn("JWT validation failed - auth_time '{}' is in the future", authTime)
                return null
            }
        } catch (e: Exception) {
            log.warn("JWT validation failed - Invalid auth_time format: {}", e.message)
            return null
        }

        return Unit
    }

    private fun setupAuthentication(request: HttpServletRequest, decodedJWT: DecodedJWT) {
        val userId = decodedJWT.subject
        if (userId.isNullOrBlank()) {
            log.warn("JWT subject (user ID) is missing or blank. Cannot set up authentication.")
            return
        }

        val authorities = listOf(SimpleGrantedAuthority("ROLE_USER"))

        val authentication = UsernamePasswordAuthenticationToken(
            userId,
            null,
            authorities
        )

        authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
        SecurityContextHolder.getContext().authentication = authentication
    }
}