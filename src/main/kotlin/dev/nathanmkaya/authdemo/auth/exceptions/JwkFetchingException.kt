package dev.nathanmkaya.authdemo.auth.exceptions

class JwkFetchingException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
