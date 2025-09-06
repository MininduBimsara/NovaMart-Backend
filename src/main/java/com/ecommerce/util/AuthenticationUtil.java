// src/main/java/com/ecommerce/util/AuthenticationUtil.java - NEW UTILITY
package com.ecommerce.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationUtil {

    /**
     * UNIFIED username extraction that works for both Asgardeo and local JWT tokens
     */
    public static String extractUsernameFromAuth(Authentication authentication) {
        if (authentication == null) {
            log.error("Authentication is null");
            return null;
        }

        log.info("=== EXTRACTING USERNAME ===");
        log.info("Authentication type: {}", authentication.getClass().getSimpleName());
        log.info("Principal type: {}", authentication.getPrincipal().getClass().getSimpleName());
        log.info("Authentication name: {}", authentication.getName());

        // CASE 1: Asgardeo JWT tokens (OAuth2)
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            log.info("Processing Asgardeo JWT token");
            log.info("Available JWT claims: {}", jwt.getClaims().keySet());

            // PRIORITY ORDER for Asgardeo:

            // 1. preferred_username (most reliable for Asgardeo)
            String username = jwt.getClaimAsString("preferred_username");
            if (isValidUsername(username)) {
                log.info("Using preferred_username: {}", username);
                return username;
            }

            // 2. email (common fallback for Asgardeo)
            username = jwt.getClaimAsString("email");
            if (isValidUsername(username)) {
                log.info("Using email as username: {}", username);
                return username;
            }

            // 3. sub (subject - unique identifier)
            username = jwt.getSubject();
            if (isValidUsername(username)) {
                log.info("Using subject as username: {}", username);
                return username;
            }

            // 4. name (display name as last resort)
            username = jwt.getClaimAsString("name");
            if (isValidUsername(username)) {
                log.info("Using name as username: {}", username);
                return username;
            }
        }

        // CASE 2: Local JWT tokens (string principal from our JWT filter)
        String name = authentication.getName();
        if (isValidUsername(name)) {
            log.info("Using authentication name (local JWT): {}", name);
            return name;
        }

        // CASE 3: String principal directly
        Object principal = authentication.getPrincipal();
        if (principal instanceof String stringPrincipal && isValidUsername(stringPrincipal)) {
            log.info("Using string principal: {}", stringPrincipal);
            return stringPrincipal;
        }

        // CASE 4: UserDetails (if somehow used)
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails userDetails) {
            log.info("Using UserDetails username: {}", userDetails.getUsername());
            return userDetails.getUsername();
        }

        log.error("Could not extract username from authentication: {}", authentication);
        return null;
    }

    /**
     * Check if user has admin role
     */
    public static boolean isAdmin(Authentication authentication) {
        if (authentication == null) {
            return false;
        }

        boolean hasAdminAuthority = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority -> {
                    String auth = authority.toUpperCase();
                    return auth.equals("ROLE_ADMIN") ||
                            auth.equals("ADMIN") ||
                            auth.equals("ROLE_ADMINISTRATOR") ||
                            auth.equals("ADMINISTRATOR");
                });

        log.debug("Admin check - Has admin authority: {}", hasAdminAuthority);
        return hasAdminAuthority;
    }

    /**
     * Validate if username is usable
     */
    private static boolean isValidUsername(String username) {
        return username != null &&
                !username.trim().isEmpty() &&
                !username.equals("anonymousUser");
    }

    /**
     * Extract user display name for UI purposes
     */
    public static String extractDisplayName(Authentication authentication) {
        if (authentication == null) {
            return null;
        }

        if (authentication.getPrincipal() instanceof Jwt jwt) {
            // Try name claim first
            String name = jwt.getClaimAsString("name");
            if (isValidUsername(name)) {
                return name;
            }

            // Try constructing from given_name and family_name
            String givenName = jwt.getClaimAsString("given_name");
            String familyName = jwt.getClaimAsString("family_name");

            if (givenName != null && familyName != null) {
                return givenName + " " + familyName;
            } else if (givenName != null) {
                return givenName;
            }

            // Fallback to email or username
            String email = jwt.getClaimAsString("email");
            if (isValidUsername(email)) {
                return email;
            }
        }

        // Fallback to authentication name
        return authentication.getName();
    }
}