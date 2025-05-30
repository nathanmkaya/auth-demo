Okay, here's a detailed list of TODOs to improve the codebase, incorporating the previous suggestions and additional best practices found by looking online.

## Detailed TODO List for Codebase Improvement

**I. Security Enhancements & JWT Handling (High Priority)**

*   **[DONE - Partially, Needs Verification] `GooglePublicKeyService.kt`: Implement Robust JWK Parsing using JJWT**
    *   **Action:** Modify `fetchJwkSet` to use `Jwks.parser().build(keyMap)` for parsing individual keys from the Google JWK Set, as detailed in `Implementation.md` and the previous improvement suggestion.
    *   **Benefit:** More robust, handles various key types correctly, less manual code, leverages library features.
    *   **Reference:** `Implementation.md` (Section 3.2), JJWT documentation.
*   **[DONE - Partially, Needs Verification] `JwtAuthFilter.kt`: Utilize JJWT's `SigningKeyResolverAdapter` and Built-in Claim Validation**
    *   **Action:** Refactor `validateToken` to use `Jwts.parser().setSigningKeyResolver(...)`, `.requireIssuerIn(...)`, and `.requireAudienceIn(...)` as shown in `Implementation.md`.
    *   **Benefit:** Cleaner, more idiomatic use of JJWT, reduces manual validation logic.
    *   **Reference:** `Implementation.md` (Section 4, JwtAuthFilter.kt example).
*   **[TODO] Token Revocation Strategy (Advanced):**
    *   **Action:** Research and consider implementing a token revocation mechanism if immediate revocation is a requirement (e.g., user changes password, account compromised). This often involves a blacklist (e.g., in Redis or a database) checked during validation. Firebase itself handles some revocation cases, but custom backend logic might be needed for others.
    *   **Benefit:** Enhanced security by allowing invalidation of tokens before their natural expiry.
    *   **Online Search:** "jwt revocation strategies spring boot", "firebase token revocation backend".
*   **[TODO] Secure `kid` Handling:**
    *   **Action:** Ensure that the `kid` from the JWT header is strictly validated and that the `GooglePublicKeyService` only returns keys that are expected/valid for your application. While fetching from Google's official URI is generally safe, be mindful if the source of JWKs could ever be less trusted.
    *   **Benefit:** Prevents potential vulnerabilities if an attacker could somehow influence the `kid` to point to a malicious key.
*   **[TODO] Input Validation on Token:**
    *   **Action:** Although JJWT handles parsing, ensure any claims extracted and used beyond authentication (e.g., if you were to use other custom claims) are validated for expected format/content.
    *   **Benefit:** Defense in depth.
*   **[TODO] Principle of Least Privilege for Roles/Authorities:**
    *   **Action:** Currently, a default `ROLE_USER` is assigned. If your application has different user roles or permissions, fetch these from your user database based on the `userId` (Firebase UID) and assign more granular authorities.
    *   **Benefit:** Finer-grained access control.
*   **[TODO] Review HTTP Security Headers:**
    *   **Action:** Ensure appropriate security headers are being set (e.g., `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`). Spring Security can help configure these.
    *   **Benefit:** Protects against common web vulnerabilities like XSS, clickjacking.
    *   **Online Search:** "spring security http headers".

**II. Code Quality, Readability & Maintainability**

*   **[TODO] Use `@ConfigurationProperties` for Application Properties:**
    *   **Action:** Refactor `firebase.project-ids` and `google.jwk-set-uri` to be managed by dedicated `@ConfigurationProperties` classes (e.g., `FirebaseProperties`, `GoogleJwkProperties`).
    *   **Benefit:** Type safety, validation, better organization, easier refactoring.
*   **[TODO] Consistent Logging:**
    *   **Action:** Review all log statements. Ensure consistent log levels (INFO for lifecycle events, DEBUG for detailed flow, WARN for recoverable issues, ERROR for critical failures). Log key identifiers (like `kid`, `userId`, relevant claims) to aid debugging. Avoid logging sensitive data.
    *   **Benefit:** Improved debuggability and monitoring.
*   **[TODO] Kotlin Idioms and Style:**
    *   **Action:** Review the Kotlin code for more idiomatic expressions, use of extension functions where appropriate, null safety enforcement, and adherence to Kotlin coding conventions.
    *   **Benefit:** More concise, readable, and maintainable Kotlin code.
    *   **Online Search:** "kotlin idiomatic code", "kotlin style guide".
*   **[TODO] Specific Custom Exceptions:**
    *   **Action:** Instead of generic `RuntimeException` in `GooglePublicKeyService` (e.g., for JWK fetching failures), define and use more specific custom exceptions (e.g., `JwkFetchingException`, `JwkParsingException`).
    *   **Benefit:** Allows for more granular error handling by callers.
*   **[TODO] Asynchronous Operations for JWK Fetching (Consider):**
    *   **Action:** The `GooglePublicKeyService.fetchJwkSet` uses `.block()`. While caching mitigates frequent blocking, consider if the initial fetch (or cache miss) could be made non-blocking if it impacts startup time or request handling in a highly concurrent environment. This would involve returning a `Mono<Map<String, Jwk<*>>>` and having the caller handle the reactive chain.
    *   **Benefit:** Improved responsiveness under certain conditions, aligns better with WebFlux if used more extensively.
    *   **Note:** This adds complexity, so weigh the benefits against it. Caching makes this less critical for subsequent calls.
*   **[TODO] Refine `JwtAuthFilter` Exception Handling:**
    *   **Action:** Ensure the `catch` blocks in `validateToken` provide enough context. The current logging is good, but double-check if any specific exception types from JJWT could be handled or logged more informatively.
    *   **Benefit:** Better diagnostics for token validation issues.
*   **[TODO] Remove Unused Imports and Variables:**
    *   **Action:** Perform a pass to clean up any unused imports or declared variables. IDEs can usually automate this.
    *   **Benefit:** Cleaner code.

**III. Testing (High Priority)**

*   **[TODO] Unit Tests for `GooglePublicKeyService`:**
    *   **Action:**
        *   Mock `WebClient` to simulate successful JWK set responses (valid JSON, empty keys array, malformed JSON).
        *   Test parsing logic (ensure correct keys are extracted or errors are thrown).
        *   Test caching behavior (e.g., `WebClient` mock is called only once for subsequent calls to `getPublicKey` with the same `kid` within cache expiry).
        *   Test `getPublicKey` for known `kid`, unknown `kid`, and JWK without a `key` object.
    *   **Benefit:** Ensures key fetching and parsing logic is correct and resilient.
*   **[TODO] Unit Tests for `JwtAuthFilter`:**
    *   **Action:**
        *   Test `extractToken` with valid "Bearer" token, missing token, malformed header.
        *   Test `validateToken` with:
            *   Valid token (mock `GooglePublicKeyService` to provide the key).
            *   Expired token.
            *   Token with invalid signature.
            *   Token with incorrect issuer/audience.
            *   Token missing required claims (e.g., `kid`).
            *   Malformed token.
        *   Test `setupAuthentication` ensures `SecurityContextHolder` is populated correctly.
        *   Test the overall `doFilterInternal` logic flow for different token scenarios.
    *   **Benefit:** Verifies the core authentication logic.
*   **[TODO] Integration Tests for `SecurityConfig` and `UserController`:**
    *   **Action:**
        *   Use `@SpringBootTest` and `MockMvc`.
        *   Test `/api/user/me` and other secured endpoints:
            *   Without any token (expect 401/403).
            *   With a valid, properly signed JWT (requires mocking `GooglePublicKeyService` or setting up a test JWK source and generating a test token).
            *   With an invalid/expired JWT.
        *   Test public endpoints like `/actuator/health` are accessible without a token.
    *   **Benefit:** Ensures the security filter chain and endpoint protection work as expected.
*   **[TODO] Test Token Generation (Helper for Integration Tests):**
    *   **Action:** Create a test utility to generate valid (signed with a known private key) and invalid JWTs for your integration tests. The public key corresponding to the private key used for signing would be served by your mocked `GooglePublicKeyService`.
    *   **Benefit:** Reliable and controllable token generation for testing.

**IV. Configuration & Dependencies**

*   **[TODO] Review Spring Boot and Kotlin Versions:**
    *   **Action:** As mentioned before, Spring Boot `3.4.0` is very new. For production, consider aligning with the latest stable GA release (e.g., `3.2.x` or `3.3.x` if available and stable by the time of implementation). Same for Kotlin `2.1.20`.
    *   **Benefit:** Stability and wider community support.
*   **[TODO] Dependency Audit:**
    *   **Action:** Regularly audit dependencies for known vulnerabilities using tools like OWASP Dependency-Check, Snyk, or GitHub's Dependabot.
    *   **Benefit:** Proactive security patching.
*   **[TODO] Fine-tune Cache Configuration:**
    *   **Action:** The current `expireAfterWrite=24h` for JWKs is reasonable as Google's keys don't rotate extremely frequently. However, monitor Google's documentation for any changes in recommended caching duration. The `Cache-Control` header from Google's JWK URI (`https://www.googleapis.com/robot/v1/keys`) often indicates the max age.
    *   **Benefit:** Optimal balance between performance and key freshness.
    *   **Current `Cache-Control` (as of May 2024):** `public, max-age=22000, must-revalidate, no-transform` (approx 6 hours). Your 24h cache might be too long if strict adherence to `max-age` is desired. Consider reducing `expireAfterWrite`.

**V. Documentation & Readme**

*   **[TODO] Update `Implementation.md`:**
    *   **Action:**
        *   Correct the `allowedIssuers` line in the `JwtAuthFilter.kt` example to remove the Markdown link.
        *   Ensure the code snippets in `Implementation.md` reflect the improved JWK parsing and `SigningKeyResolverAdapter` usage once implemented.
    *   **Benefit:** Accurate documentation.
*   **[TODO] Enhance `README.md`:**
    *   **Action:**
        *   Add a section on how to generate a sample Firebase ID token for testing (e.g., using a simple Firebase client app or Firebase CLI).
        *   Briefly mention the caching strategy for public keys.
        *   Consider adding a small "Troubleshooting" section for common issues (e.g., token expired, issuer mismatch).
    *   **Benefit:** Better developer experience for users of the demo.
*   **[TODO] Add KDoc/JavaDoc:**
    *   **Action:** Add KDoc comments to public classes and methods, especially in the `auth` package, explaining their purpose, parameters, and return values.
    *   **Benefit:** Improved code understanding and maintainability.

**VI. Operational Considerations**

*   **[TODO] Structured Logging (JSON):**
    *   **Action:** Consider configuring logging to output in a structured format like JSON. This makes logs much easier to parse, search, and analyze in log management systems (e.g., ELK stack, Splunk).
    *   **Benefit:** Improved observability in production.
    *   **Online Search:** "spring boot json logging logback".
*   **[TODO] Health Check for JWK Fetching:**
    *   **Action:** Consider adding a custom Spring Boot Actuator health indicator that checks if the application can successfully fetch and parse the JWK set from Google.
    *   **Benefit:** Early detection of problems with a critical dependency.
    *   **Online Search:** "spring boot custom health indicator".
*   **[TODO] Rate Limiting (If applicable):**
    *   **Action:** If the API is public-facing or could be abused, consider implementing rate limiting.
    *   **Benefit:** Protects against denial-of-service attacks and abuse.
    *   **Online Search:** "spring boot rate limiting".

This comprehensive list should provide a good roadmap for further enhancing the codebase. Prioritize based on the impact and effort for each item. Security and testing items usually offer the highest initial value.