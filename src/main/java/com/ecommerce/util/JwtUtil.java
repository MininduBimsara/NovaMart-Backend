package com.ecommerce.util;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    /**
     * Extracts username from JWT token using multiple fallback strategies
     */
    public static String extractUsername(Jwt jwt) {
        // Try preferred_username (common in OIDC)
        String username = jwt.getClaimAsString("preferred_username");
        if (username != null && !username.trim().isEmpty()) {
            return username;
        }

        // Try username claim
        username = jwt.getClaimAsString("username");
        if (username != null && !username.trim().isEmpty()) {
            return username;
        }

        // Try email as username
        username = jwt.getClaimAsString("email");
        if (username != null && !username.trim().isEmpty()) {
            return username;
        }

        // Fallback to subject
        return jwt.getSubject();
    }

    /**
     * Extracts user's full name from JWT token
     */
    public static String extractFullName(Jwt jwt) {
        String name = jwt.getClaimAsString("name");
        if (name != null && !name.trim().isEmpty()) {
            return name;
        }

        // Construct from given_name and family_name
        String givenName = jwt.getClaimAsString("given_name");
        String familyName = jwt.getClaimAsString("family_name");

        if (givenName != null && familyName != null) {
            return givenName + " " + familyName;
        } else if (givenName != null) {
            return givenName;
        } else if (familyName != null) {
            return familyName;
        }

        return null;
    }

    /**
     * Extracts email from JWT token
     */
    public static String extractEmail(Jwt jwt) {
        return jwt.getClaimAsString("email");
    }

    /**
     * Extracts phone number from JWT token
     */
    public static String extractPhoneNumber(Jwt jwt) {
        return jwt.getClaimAsString("phone_number");
    }

    /**
     * Extracts roles from JWT token
     */
    @SuppressWarnings("unchecked")
    public static List<String> extractRoles(Jwt jwt) {
        // Try groups claim (Asgardeo uses this)
        Object roles = jwt.getClaim("groups");
        if (roles == null) {
            roles = jwt.getClaim("roles");
        }
        if (roles == null) {
            roles = jwt.getClaim("authorities");
        }
        if (roles == null) {
            roles = jwt.getClaim("application_roles");
        }

        if (roles instanceof List<?>) {
            return ((List<?>) roles).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
        } else if (roles instanceof String) {
            return List.of(roles.toString().split("[\\s,]+"));
        }

        return List.of("USER"); // Default role
    }

    /**
     * Checks if user has a specific role
     */
    public static boolean hasRole(Jwt jwt, String role) {
        List<String> roles = extractRoles(jwt);
        return roles.contains(role.toUpperCase()) || roles.contains("ROLE_" + role.toUpperCase());
    }

    /**
     * Checks if user is admin
     */
    public static boolean isAdmin(Jwt jwt) {
        return hasRole(jwt, "ADMIN");
    }

    /**
     * Checks if JWT token is expired
     */
    public static boolean isTokenExpired(Jwt jwt) {
        Instant expiresAt = jwt.getExpiresAt();
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }

    /**
     * Gets remaining time until token expires (in seconds)
     */
    public static long getTimeToExpiry(Jwt jwt) {
        Instant expiresAt = jwt.getExpiresAt();
        if (expiresAt == null) {
            return 0;
        }
        return Math.max(0, expiresAt.getEpochSecond() - Instant.now().getEpochSecond());
    }

    /**
     * Extracts scopes from JWT token
     */
    @SuppressWarnings("unchecked")
    public static List<String> extractScopes(Jwt jwt) {
        String scope = jwt.getClaimAsString("scope");
        if (scope != null && !scope.trim().isEmpty()) {
            return List.of(scope.split("\\s+"));
        }

        // Check scp claim (some providers use this)
        Object scp = jwt.getClaim("scp");
        if (scp instanceof List<?>) {
            return ((List<?>) scp).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
        } else if (scp instanceof String) {
            return List.of(scp.toString().split("\\s+"));
        }

        return List.of();
    }

    /**
     * Extracts user's locale/country from JWT token
     */
    public static String extractLocale(Jwt jwt) {
        return jwt.getClaimAsString("locale");
    }

    /**
     * Checks if email is verified
     */
    public static boolean isEmailVerified(Jwt jwt) {
        Boolean verified = jwt.getClaimAsBoolean("email_verified");
        return verified != null && verified;
    }
}