package dev.nathanmkaya.authdemo.auth

import io.jsonwebtoken.*
import io.jsonwebtoken.security.SecurityException
import io.jsonwebtoken.security.SigningKeyResolverAdapter
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

@Component
class JwtAuthFilter(
    private val googlePublicKeyService: GooglePublicKeyService
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(JwtAuthFilter::class.java)

    @Value("\${firebase.project-ids}")
    private lateinit var allowedFirebaseProjectIds: List<String>

    private val allowedIssuers: Set<String> by lazy {
        allowedFirebaseProjectIds.map { "https://securetoken.google.com/$it" }.toSet()
    }
    private val allowedAudiences: Set<String> by lazy {
        allowedFirebaseProjectIds.toSet()
    }

    private val signingKeyResolver = object : SigningKeyResolverAdapter() {
        override fun resolveSigningKey(header: JwsHeader<*>?): Key {
            val keyId = header?.keyId ?: throw UnsupportedJwtException("JWT header does not contain 'kid' claim.")
            try {
                return googlePublicKeyService.getPublicKey(keyId)
            } catch (e: Exception) {
                log.error("Failed to resolve signing key for kid '{}': {}", keyId, e.message)
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
                    SecurityContextHolder.clearContext()
                }
            } else {
                log.trace("No JWT token found in Authorization header.")
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
            val parser: JwtParser = Jwts.parser()
                .setSigningKeyResolver(signingKeyResolver)
                .requireIssuerIn(allowedIssuers)
                .requireAudienceIn(allowedAudiences)
                .build()

            val jws: Jws<Claims> = parser.parseSignedClaims(token)
            return jws.payload

        } catch (ex: MissingClaimException) {
            log.warn("JWT validation failed - Missing required claim [{}]: {}", ex.header, ex.message)
        } catch (ex: IncorrectClaimException) {
            log.warn("JWT validation failed - Incorrect claim [{}]: {}", ex.header, ex.message)
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