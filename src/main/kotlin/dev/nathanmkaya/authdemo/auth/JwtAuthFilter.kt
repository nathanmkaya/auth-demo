package dev.nathanmkaya.authdemo.auth

import dev.nathanmkaya.authdemo.config.FirebaseProperties
import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.IncorrectClaimException
import io.jsonwebtoken.Jws
import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.MissingClaimException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.security.SecurityException
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

/**
 * JWT authentication filter that validates Firebase ID tokens on incoming requests.
 * 
 * This filter extracts JWT tokens from the Authorization header, validates them using
 * Google's public keys, and sets up Spring Security authentication context for valid tokens.
 * It supports multiple Firebase project IDs and validates both the issuer and audience claims.
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
                    log.debug("JWT Authentication successful for userId: {}, issuer: {}", 
                        claims.subject, claims.issuer)
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

    private fun validateToken(token: String): Claims? {
        try {
            // Build the parser with keyLocator for signature verification
            // Note: JJWT's built-in require methods only support single values, but we need to support
            // multiple Firebase project IDs, so we perform manual validation after parsing
            val parser: JwtParser = Jwts.parser()
                .keyLocator { header ->
                    val keyId = header["kid"] as? String ?: throw UnsupportedJwtException("JWT header does not contain 'kid' claim.")
                    try {
                        log.debug("Resolving signing key for kid: {}", keyId)
                        googlePublicKeyService.getPublicKey(keyId)
                    } catch (e: Exception) {
                        log.error("Failed to resolve signing key for kid '{}': {}", keyId, e.message)
                        throw SecurityException("Could not resolve signing key for kid '$keyId'", e)
                    }
                }
                // Expiration (exp) and Not Before (nbf) are checked by default
                .build()

            // Parse the token and verify signature + expiration
            val jws: Jws<Claims> = parser.parseSignedClaims(token)
            val claims = jws.payload

            // Validate issuer against allowed list (supports multiple Firebase projects)
            val issuer = claims.issuer
            if (!allowedIssuers.contains(issuer)) {
                log.warn("JWT validation failed - Invalid issuer: '{}'. Expected one of: [{}]", 
                    issuer, allowedIssuers.joinToString(", "))
                return null
            }
            
            // Validate audience against allowed list (supports multiple Firebase projects)
            val audience = claims.audience?.toString()
            if (!allowedAudiences.contains(audience)) {
                log.warn("JWT validation failed - Invalid audience: '{}'. Expected one of: [{}]", 
                    audience, allowedAudiences.joinToString(", "))
                return null
            }

            return claims

        } catch (ex: MissingClaimException) {
            log.warn("JWT validation failed - Missing required claim: {}", ex.message)
        } catch (ex: IncorrectClaimException) {
            log.warn("JWT validation failed - Incorrect claim: {}", ex.message)
        } catch (ex: SecurityException) {
            log.warn("Invalid JWT signature or key issue: {}", ex.message)
        } catch (ex: MalformedJwtException) {
            log.warn("Invalid JWT token format: {}", ex.message)
        } catch (ex: ExpiredJwtException) {
            log.warn("Expired JWT token used: {}", ex.message)
        } catch (ex: UnsupportedJwtException) {
            log.warn("Unsupported JWT token type or structure: {}", ex.message)
        } catch (ex: IllegalArgumentException) {
            log.warn("JWT processing failed due to invalid argument: {}", ex.message)
        } catch (e: Exception) {
            log.error("Unexpected error during JWT validation: {}", e.message, e)
        }
        return null
    }

    private fun setupAuthentication(request: HttpServletRequest, claims: Claims) {
        val userId = claims.subject
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