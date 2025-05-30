package dev.nathanmkaya.authdemo.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "google")
data class GoogleJwkProperties(
    val jwkSetUri: String
)