package dev.nathanmkaya.authdemo.auth

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.cache.annotation.Cacheable
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import java.security.Key

@Service
class GooglePublicKeyService(private val webClientBuilder: WebClient.Builder) {

    private val log = LoggerFactory.getLogger(GooglePublicKeyService::class.java)

    @Value("\${google.jwk-set-uri}")
    private lateinit var jwkSetUri: String

    @Cacheable("googleJwkSet")
    fun fetchJwkSet(): Map<String, Jwk<*>> {
        log.info("Fetching Google JWK Set from {}", jwkSetUri)
        try {
            val responseBody = webClientBuilder.build()
                .get()
                .uri(jwkSetUri)
                .retrieve()
                .bodyToMono<String>()
                .block()

            if (responseBody == null) {
                log.error("Received empty response body from JWK Set URI: {}", jwkSetUri)
                throw RuntimeException("Failed to fetch JWK Set: Empty response")
            }

            val objectMapper = ObjectMapper()
            val jwkMap: Map<String, List<Map<String, Any>>> = objectMapper.readValue(responseBody, object : TypeReference<Map<String, List<Map<String, Any>>>>() {})
            val keysList = jwkMap["keys"] ?: throw RuntimeException("JWK Set JSON does not contain 'keys' array")

            val parsedJwks = keysList.mapNotNull { keyMap ->
                try {
                    Jwks.parser().build(keyMap)
                } catch (e: Exception) {
                    log.warn("Failed to parse individual JWK: {}. Skipping.", keyMap, e)
                    null
                }
            }

            if (parsedJwks.isEmpty()) {
                throw RuntimeException("No valid JWKs could be parsed from the fetched set at $jwkSetUri")
            }

            return parsedJwks.associateBy {
                it.id ?: throw IllegalArgumentException("Parsed JWK is missing 'kid'. Key map: $it")
            }

        } catch (e: Exception) {
            log.error("Failed to fetch or parse Google JWK Set from {}: {}", jwkSetUri, e.message, e)
            throw RuntimeException("Failed to obtain Google public keys from $jwkSetUri", e)
        }
    }

    fun getPublicKey(kid: String): Key {
        val jwkSetMap = fetchJwkSet()
        val jwk = jwkSetMap[kid] ?: throw UnsupportedJwtException("JWT Key ID '$kid' not found in cached/fetched JWK Set from $jwkSetUri")

        return jwk.key ?: throw UnsupportedJwtException("JWK '$kid' from $jwkSetUri did not produce a usable Key object.")
    }
}