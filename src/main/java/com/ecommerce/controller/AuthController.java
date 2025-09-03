package com.ecommerce.controller;

import com.ecommerce.dto.AuthenticationDTO;
import com.ecommerce.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "JWT Authentication and token management")
public class AuthController {

    private final AuthenticationService authenticationService;

    @Value("${spring.security.oauth2.client.registration.asgardeo.client-id:}")
    private String clientId;

    @Value("${spring.security.oauth2.client.provider.asgardeo.authorization-uri:}")
    private String authorizationUri;

    // Local JWT Authentication endpoints

    @PostMapping("/login")
    @Operation(summary = "User Login", description = "Authenticates user with username/email and password, returns JWT token")
    public ResponseEntity<AuthenticationDTO.LoginResponse> login(@Valid @RequestBody AuthenticationDTO.LoginRequest loginRequest) {
        AuthenticationDTO.LoginResponse response = authenticationService.login(loginRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    @Operation(summary = "User Logout", description = "Invalidates the JWT token")
    public ResponseEntity<Map<String, String>> logout(@Valid @RequestBody AuthenticationDTO.LogoutRequest logoutRequest) {
        authenticationService.logout(logoutRequest.getToken());

        Map<String, String> response = new HashMap<>();
        response.put("message", "Successfully logged out");
        response.put("status", "success");

        return ResponseEntity.ok(response);
    }

    @PostMapping("/validate-token")
    @Operation(summary = "Validate JWT token", description = "Validates the provided JWT token and returns token info")
    public ResponseEntity<AuthenticationDTO.TokenValidationResponse> validateToken(@Valid @RequestBody Map<String, String> request) {
        String token = request.get("token");
        if (token == null || token.trim().isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        // Remove Bearer prefix if present
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        AuthenticationDTO.TokenValidationResponse response = authenticationService.validateToken(token);
        return ResponseEntity.ok(response);
    }

    // OAuth2/Asgardeo endpoints (existing functionality)

    @GetMapping("/login-url")
    @Operation(summary = "Get Asgardeo login URL", description = "Returns the URL for Asgardeo OAuth2 login")
    public ResponseEntity<LoginUrlResponse> getLoginUrl(@RequestParam(defaultValue = "http://localhost:3000/callback") String redirectUri) {
        if (clientId == null || clientId.isEmpty() || authorizationUri == null || authorizationUri.isEmpty()) {
            return ResponseEntity.ok(LoginUrlResponse.builder()
                    .loginUrl("")
                    .clientId("")
                    .message("Asgardeo OAuth2 not configured. Use /api/auth/login for local authentication.")
                    .build());
        }

        String loginUrl = String.format(
                "%s?client_id=%s&response_type=code&scope=openid%%20profile%%20email&redirect_uri=%s",
                authorizationUri, clientId, redirectUri
        );

        return ResponseEntity.ok(LoginUrlResponse.builder()
                .loginUrl(loginUrl)
                .clientId(clientId)
                .build());
    }

    @GetMapping("/profile")
    @Operation(summary = "Get authenticated user profile", description = "Returns the profile information from JWT token (OAuth2 or local)")
    public ResponseEntity<UserProfile> getUserProfile(@AuthenticationPrincipal Jwt jwt) {
        UserProfile profile = UserProfile.builder()
                .sub(jwt.getSubject())
                .username(extractUsername(jwt))
                .name(jwt.getClaimAsString("name"))
                .givenName(jwt.getClaimAsString("given_name"))
                .familyName(jwt.getClaimAsString("family_name"))
                .email(jwt.getClaimAsString("email"))
                .emailVerified(jwt.getClaimAsBoolean("email_verified"))
                .phoneNumber(jwt.getClaimAsString("phone_number"))
                .locale(jwt.getClaimAsString("locale"))
                .roles(extractRoles(jwt))
                .scopes(extractScopes(jwt))
                .issuedAt(jwt.getIssuedAt())
                .expiresAt(jwt.getExpiresAt())
                .build();

        return ResponseEntity.ok(profile);
    }

    @PostMapping("/validate")
    @Operation(summary = "Validate OAuth2 JWT token", description = "Validates OAuth2 JWT token and returns token info")
    public ResponseEntity<TokenValidationResponse> validateOAuth2Token(@AuthenticationPrincipal Jwt jwt) {
        boolean isValid = jwt.getExpiresAt() != null && jwt.getExpiresAt().isAfter(Instant.now());

        TokenValidationResponse response = TokenValidationResponse.builder()
                .valid(isValid)
                .subject(jwt.getSubject())
                .username(extractUsername(jwt))
                .roles(extractRoles(jwt))
                .issuedAt(jwt.getIssuedAt())
                .expiresAt(jwt.getExpiresAt())
                .timeToExpiry(isValid ? jwt.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond() : 0)
                .build();

        return ResponseEntity.ok(response);
    }

    @GetMapping("/config")
    @Operation(summary = "Get OAuth2 configuration", description = "Returns OAuth2 configuration for frontend")
    public ResponseEntity<Map<String, String>> getOAuth2Config() {
        Map<String, String> config = new HashMap<>();
        config.put("clientId", clientId != null ? clientId : "");
        config.put("authorizationUri", authorizationUri != null ? authorizationUri : "");
        config.put("scope", "openid profile email");
        config.put("responseType", "code");
        config.put("hasOAuth2", String.valueOf(clientId != null && !clientId.isEmpty()));

        return ResponseEntity.ok(config);
    }

    // Helper methods
    private String extractUsername(Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        if (username == null) {
            username = jwt.getClaimAsString("username");
        }
        if (username == null) {
            username = jwt.getClaimAsString("email");
        }
        if (username == null) {
            username = jwt.getSubject();
        }
        return username;
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Jwt jwt) {
        Object roles = null;

        // Check for various role claims
        if (jwt.hasClaim("groups")) {
            roles = jwt.getClaim("groups");
        } else if (jwt.hasClaim("roles")) {
            roles = jwt.getClaim("roles");
        }

        if (roles instanceof List<?>) {
            return ((List<?>) roles).stream()
                    .map(Object::toString)
                    .toList();
        }
        return List.of();
    }

    @SuppressWarnings("unchecked")
    private List<String> extractScopes(Jwt jwt) {
        String scope = jwt.getClaimAsString("scope");
        if (scope != null) {
            return List.of(scope.split("\\s+"));
        }
        return List.of();
    }

    // Response DTOs
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LoginUrlResponse {
        private String loginUrl;
        private String clientId;
        private String message;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserProfile {
        private String sub;
        private String username;
        private String name;
        private String givenName;
        private String familyName;
        private String email;
        private Boolean emailVerified;
        private String phoneNumber;
        private String locale;
        private List<String> roles;
        private List<String> scopes;
        private Instant issuedAt;
        private Instant expiresAt;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TokenValidationResponse {
        private boolean valid;
        private String subject;
        private String username;
        private List<String> roles;
        private Instant issuedAt;
        private Instant expiresAt;
        private long timeToExpiry;
    }
}