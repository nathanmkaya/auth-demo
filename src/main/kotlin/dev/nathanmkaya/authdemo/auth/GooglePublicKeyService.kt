package dev.nathanmkaya.authdemo.auth

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import dev.nathanmkaya.authdemo.auth.exceptions.JwkFetchingException
import dev.nathanmkaya.authdemo.auth.exceptions.JwkParsingException
import dev.nathanmkaya.authdemo.config.GoogleJwkProperties
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import org.slf4j.LoggerFactory
import org.springframework.cache.annotation.Cacheable
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import java.security.Key

/**
 * Service for fetching and caching Google's public keys used to verify Firebase ID tokens.
 * 
 * This service fetches JWK (JSON Web Key) sets from Google's public endpoints and parses
 * them into RSA public keys that can be used for JWT signature verification.
 */
@Service
class GooglePublicKeyService(
    private val webClientBuilder: WebClient.Builder,
    private val googleJwkProperties: GoogleJwkProperties
) {

    private val log = LoggerFactory.getLogger(GooglePublicKeyService::class.java)

    /**
     * Fetches and parses the Google JWK set from the configured URI.
     * 
     * This method is cached to avoid repeated network calls to Google's endpoints.
     * The cache is configured to expire based on Google's Cache-Control headers.
     * Uses JJWT's built-in Jwks parser for robust key parsing.
     * 
     * @return Map of key IDs to their corresponding Jwk objects
     * @throws JwkFetchingException if the JWK set cannot be fetched from Google
     * @throws JwkParsingException if the fetched JWK set cannot be parsed
     */
    @Cacheable("googleJwkSet")
    fun fetchJwkSet(): Map<String, Jwk<*>> {
        log.info("Fetching Google JWK Set from {}", googleJwkProperties.jwkSetUri)
        try {
            val responseBody = webClientBuilder.build()
                .get()
                .uri(googleJwkProperties.jwkSetUri)
                .retrieve()
                .bodyToMono<String>()
                .block()

            if (responseBody == null) {
                log.error("Received empty response body from JWK Set URI: {}", googleJwkProperties.jwkSetUri)
                throw JwkFetchingException("Failed to fetch JWK Set: Empty response")
            }

            // Parse the top-level structure using Jackson
            val objectMapper = ObjectMapper()
            val jwkMap: Map<String, List<Map<String, Any>>> = objectMapper.readValue(responseBody, object : TypeReference<Map<String, List<Map<String, Any>>>>() {})
            val keysList = jwkMap["keys"] ?: throw JwkParsingException("JWK Set JSON does not contain 'keys' array")

            // Parse each key map using JJWT's Jwks parser (more robust)
            val parsedJwks = keysList.mapNotNull { keyMap ->
                try {
                    // Convert keyMap to JSON string and parse as JWK
                    val jwkJson = objectMapper.writeValueAsString(keyMap)
                    Jwks.parser().build().parse(jwkJson)
                } catch (e: Exception) {
                    log.warn("Failed to parse individual JWK with kid '{}'. Skipping. Error: {}", 
                        keyMap["kid"] ?: "unknown", e.message, e)
                    null // Return null for unparseable keys
                }
            }

            if (parsedJwks.isEmpty()) {
                throw JwkParsingException("No valid JWKs could be parsed from the fetched set at ${googleJwkProperties.jwkSetUri}")
            }

            // Create a map from kid -> Jwk for easy lookup
            val result = parsedJwks.associateBy { jwk ->
                jwk.id ?: throw JwkParsingException("Parsed JWK is missing 'kid'. JWK: $jwk")
            }

            log.info("Successfully parsed {} public keys", result.size)
            return result

        } catch (e: Exception) {
            log.error("Failed to fetch or parse Google JWK Set from {}: {}", googleJwkProperties.jwkSetUri, e.message, e)
            throw JwkFetchingException("Failed to obtain Google public keys from ${googleJwkProperties.jwkSetUri}", e)
        }
    }

    /**
     * Retrieves a specific public key by its key ID (kid).
     * 
     * This method uses the cached JWK set from [fetchJwkSet] to look up the key.
     * 
     * @param kid The key ID to look up
     * @return The RSA public key corresponding to the given key ID
     * @throws UnsupportedJwtException if the key ID is not found in the JWK set
     */
    fun getPublicKey(kid: String): Key {
        log.debug("Retrieving public key for kid: {}", kid)
        val jwkSetMap = fetchJwkSet()
        val jwk = jwkSetMap[kid] ?: run {
            log.error("JWT Key ID '{}' not found in JWK set. Available kids: {}", 
                kid, jwkSetMap.keys.joinToString(", "))
            throw UnsupportedJwtException("JWT Key ID '$kid' not found in cached/fetched JWK Set from ${googleJwkProperties.jwkSetUri}")
        }
        
        // Extract the actual key from the Jwk object
        return jwk.toKey() ?: throw UnsupportedJwtException("JWK '$kid' from ${googleJwkProperties.jwkSetUri} did not produce a usable Key object.")
    }
}