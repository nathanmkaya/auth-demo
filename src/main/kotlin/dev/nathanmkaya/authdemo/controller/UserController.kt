package dev.nathanmkaya.authdemo.controller

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
@RequestMapping("/api/user")
class UserController {

    @GetMapping("/me")
    fun getCurrentUser(@AuthenticationPrincipal userId: String): Map<String, Any> {
        return mapOf(
            "authenticatedUserId" to userId,
            "message" to "Successfully authenticated with Firebase JWT"
        )
    }

    @GetMapping("/me/principal")
    fun getCurrentUserPrincipal(principal: Principal): Map<String, Any> {
        return mapOf(
            "authenticatedUserIdFromPrincipal" to principal.name,
            "message" to "Successfully authenticated with Firebase JWT (via Principal)"
        )
    }

    @GetMapping("/profile")
    fun getUserProfile(@AuthenticationPrincipal userId: String): Map<String, Any> {
        return mapOf(
            "userId" to userId,
            "profile" to mapOf(
                "displayName" to "Demo User",
                "email" to "demo@example.com"
            ),
            "lastLogin" to System.currentTimeMillis()
        )
    }
}