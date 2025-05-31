package dev.nathanmkaya.authdemo.controller

import java.security.Principal
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

/**
 * REST controller for user-related endpoints that require authentication.
 *
 * All endpoints in this controller require a valid Firebase ID token to be present
 * in the Authorization header. The JWT authentication filter validates the token
 * and extracts the user ID for use in these endpoints.
 */
@RestController
@RequestMapping("/api/user")
class UserController {
    /**
     * Returns information about the currently authenticated user.
     *
     * @param userId The authenticated user ID extracted from the JWT token
     * @return Map containing the user ID and a success message
     */
    @GetMapping("/me")
    fun getCurrentUser(
        @AuthenticationPrincipal userId: String,
    ): Map<String, Any> =
        mapOf(
            "authenticatedUserId" to userId,
            "message" to "Successfully authenticated with Firebase JWT",
        )

    /**
     * Alternative endpoint to get current user information via Principal object.
     *
     * @param principal The Spring Security Principal containing user information
     * @return Map containing the user ID and a success message
     */
    @GetMapping("/me/principal")
    fun getCurrentUserPrincipal(principal: Principal): Map<String, Any> =
        mapOf(
            "authenticatedUserIdFromPrincipal" to principal.name,
            "message" to "Successfully authenticated with Firebase JWT (via Principal)",
        )

    /**
     * Returns a mock user profile for the authenticated user.
     *
     * This is a demonstration endpoint that shows how to build user-specific
     * responses using the authenticated user ID.
     *
     * @param userId The authenticated user ID extracted from the JWT token
     * @return Map containing mock profile information
     */
    @GetMapping("/profile")
    fun getUserProfile(
        @AuthenticationPrincipal userId: String,
    ): Map<String, Any> =
        mapOf(
            "userId" to userId,
            "profile" to
                mapOf(
                    "displayName" to "Demo User",
                    "email" to "demo@example.com",
                ),
            "lastLogin" to System.currentTimeMillis(),
        )
}
