package dev.nathanmkaya.authdemo.auth

import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import dev.nathanmkaya.authdemo.auth.exceptions.JwkFetchingException
import dev.nathanmkaya.authdemo.config.GoogleJwkProperties
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.net.URL
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.TimeUnit

/**
 * Service for fetching and caching Google's public keys used to verify Firebase ID tokens.
 *
 * This service uses Auth0's JwkProvider to handle JWK (JSON Web Key) fetching and caching
 * from Google's public endpoints for JWT signature verification.
 */
@Service
class GooglePublicKeyService(
    private val googleJwkProperties: GoogleJwkProperties,
) {
    private val log = LoggerFactory.getLogger(GooglePublicKeyService::class.java)

    /**
     * Auth0 JwkProvider configured with caching and rate limiting.
     * Built-in caching aligns with Google's Cache-Control headers (~6 hours).
     */
    private val jwkProvider: JwkProvider by lazy {
        try {
            val jwkUrl = URL(googleJwkProperties.jwkSetUri)
            log.info("Initializing JwkProvider for URL: {}", jwkUrl)

            JwkProviderBuilder(jwkUrl)
                .cached(10, 6, TimeUnit.HOURS) // Cache up to 10 JWKs for 6 hours
                .rateLimited(10, 1, TimeUnit.MINUTES) // Rate limit: 10 requests per minute
                .build()
        } catch (e: Exception) {
            log.error("Failed to initialize JwkProvider: {}", e.message, e)
            throw JwkFetchingException("Failed to initialize JWK provider", e)
        }
    }

    /**
     * Retrieves a specific RSA public key by its key ID (kid).
     *
     * Uses Auth0's JwkProvider which handles caching, rate limiting, and JWK parsing automatically.
     *
     * @param kid The key ID to look up
     * @return The RSA public key corresponding to the given key ID
     * @throws JwkFetchingException if the key cannot be fetched or parsed
     */
    fun getPublicKey(kid: String): RSAPublicKey {
        log.debug("Retrieving public key for kid: {}", kid)
        return try {
            val jwk = jwkProvider.get(kid)
            val publicKey = jwk.publicKey

            if (publicKey is RSAPublicKey) {
                log.debug("Successfully retrieved RSA public key for kid: {}", kid)
                publicKey
            } else {
                log.error("Retrieved key for kid '{}' is not an RSA public key: {}", kid, publicKey?.javaClass?.simpleName)
                throw JwkFetchingException("Key '$kid' is not an RSA public key")
            }
        } catch (e: Exception) {
            log.error("Failed to retrieve public key for kid '{}': {}", kid, e.message, e)
            throw JwkFetchingException("Failed to retrieve public key for kid '$kid'", e)
        }
    }
}
