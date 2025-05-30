package dev.nathanmkaya.authdemo.config

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Configuration properties for Google JWK (JSON Web Key) settings.
 * 
 * These properties are bound from application configuration with the "google" prefix.
 */
@ConfigurationProperties(prefix = "google")
data class GoogleJwkProperties(
    /** URI for fetching Google's public JWK set used to verify Firebase tokens */
    val jwkSetUri: String
)