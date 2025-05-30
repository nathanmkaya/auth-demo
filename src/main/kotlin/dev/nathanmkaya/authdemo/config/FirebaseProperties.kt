package dev.nathanmkaya.authdemo.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "firebase")
data class FirebaseProperties(
    val projectIds: List<String>
)