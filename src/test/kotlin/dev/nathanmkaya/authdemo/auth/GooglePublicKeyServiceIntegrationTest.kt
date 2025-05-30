package dev.nathanmkaya.authdemo.auth

import dev.nathanmkaya.authdemo.auth.exceptions.JwkFetchingException
import dev.nathanmkaya.authdemo.config.GoogleJwkProperties
import io.jsonwebtoken.UnsupportedJwtException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.web.reactive.function.client.WebClient
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Integration test for GooglePublicKeyService that tests against real Google JWK endpoint.
 * These tests require network access and may be slower.
 */
class GooglePublicKeyServiceIntegrationTest {

    private val realGoogleJwkProperties = GoogleJwkProperties(jwkSetUri = "https://www.googleapis.com/robot/v1/keys")
    private val webClientBuilder = WebClient.builder()
    private val googlePublicKeyService = GooglePublicKeyService(webClientBuilder, realGoogleJwkProperties)

    @Test
    fun `fetchJwkSet should successfully fetch and parse real Google JWK set`() {
        // When
        val result = googlePublicKeyService.fetchJwkSet()
        
        // Then
        assertTrue(result.isNotEmpty(), "JWK set should not be empty")
        result.values.forEach { key ->
            assertNotNull(key, "All keys should be valid")
        }
    }
    
    @Test
    fun `getPublicKey should throw UnsupportedJwtException for non-existent kid`() {
        // When & Then
        assertThrows<UnsupportedJwtException> {
            googlePublicKeyService.getPublicKey("non-existent-key-id")
        }
    }
    
    @Test
    fun `fetchJwkSet should throw JwkFetchingException for invalid URI`() {
        // Given
        val invalidProperties = GoogleJwkProperties(jwkSetUri = "https://invalid-domain-that-does-not-exist.com/keys")
        val serviceWithInvalidUri = GooglePublicKeyService(webClientBuilder, invalidProperties)
        
        // When & Then
        assertThrows<JwkFetchingException> {
            serviceWithInvalidUri.fetchJwkSet()
        }
    }
}