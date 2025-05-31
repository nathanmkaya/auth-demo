package dev.nathanmkaya.authdemo.config

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Configuration properties for Firebase authentication settings.
 *
 * These properties are bound from application configuration with the "firebase" prefix.
 */
@ConfigurationProperties(prefix = "firebase")
data class FirebaseProperties(
    /** List of allowed Firebase project IDs for token validation */
    val projectIds: List<String>,
)
