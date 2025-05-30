package dev.nathanmkaya.authdemo.auth

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.UnsupportedJwtException
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.cache.annotation.Cacheable
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.spec.RSAPublicKeySpec
import java.util.*

@Service
class GooglePublicKeyService(private val webClientBuilder: WebClient.Builder) {

    private val log = LoggerFactory.getLogger(GooglePublicKeyService::class.java)

    @Value("\${google.jwk-set-uri}")
    private lateinit var jwkSetUri: String

    @Cacheable("googleJwkSet")
    fun fetchJwkSet(): Map<String, Key> {
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

            val keyMap = mutableMapOf<String, Key>()
            
            keysList.forEach { keyData ->
                try {
                    val kid = keyData["kid"] as? String ?: return@forEach
                    val kty = keyData["kty"] as? String ?: return@forEach
                    val use = keyData["use"] as? String ?: return@forEach
                    val n = keyData["n"] as? String ?: return@forEach
                    val e = keyData["e"] as? String ?: return@forEach

                    if (kty == "RSA" && use == "sig") {
                        val modulus = BigInteger(1, Base64.getUrlDecoder().decode(n))
                        val exponent = BigInteger(1, Base64.getUrlDecoder().decode(e))
                        
                        val spec = RSAPublicKeySpec(modulus, exponent)
                        val keyFactory = KeyFactory.getInstance("RSA")
                        val publicKey = keyFactory.generatePublic(spec)
                        
                        keyMap[kid] = publicKey
                        log.debug("Parsed RSA public key for kid: {}", kid)
                    }
                } catch (e: Exception) {
                    log.warn("Failed to parse individual JWK: {}. Skipping.", keyData, e)
                }
            }

            if (keyMap.isEmpty()) {
                throw RuntimeException("No valid JWKs could be parsed from the fetched set at $jwkSetUri")
            }

            log.info("Successfully parsed {} public keys", keyMap.size)
            return keyMap

        } catch (e: Exception) {
            log.error("Failed to fetch or parse Google JWK Set from {}: {}", jwkSetUri, e.message, e)
            throw RuntimeException("Failed to obtain Google public keys from $jwkSetUri", e)
        }
    }

    fun getPublicKey(kid: String): Key {
        val jwkSetMap = fetchJwkSet()
        return jwkSetMap[kid] ?: throw UnsupportedJwtException("JWT Key ID '$kid' not found in cached/fetched JWK Set from $jwkSetUri")
    }
}