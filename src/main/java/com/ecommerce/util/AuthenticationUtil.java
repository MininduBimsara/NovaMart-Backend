package com.ecommerce.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationUtil {

    public static String extractUsernameFromAuth(Authentication authentication) {
        if (authentication == null) {
            log.error("Authentication is null");
            return null;
        }

        log.debug("Authentication type: {}", authentication.getClass().getSimpleName());
        log.debug("Principal type: {}", authentication.getPrincipal().getClass().getSimpleName());

        // Handle JwtAuthenticationToken (Asgardeo)
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            return extractUsernameFromJwt(jwt);
        }

        // Handle JWT principal directly
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            return extractUsernameFromJwt(jwt);
        }

        // Handle String principal (local JWT)
        if (authentication.getPrincipal() instanceof String) {
            String principal = (String) authentication.getPrincipal();
            if (isValidUsername(principal)) {
                return principal;
            }
        }

        // Fallback to getName()
        String name = authentication.getName();
        if (isValidUsername(name)) {
            return name;
        }

        log.error("Could not extract username from authentication");
        return null;
    }

    private static String extractUsernameFromJwt(Jwt jwt) {
        // Try multiple claim names in order of preference
        String[] claimNames = {
                "preferred_username",
                "email",
                "username",
                "user_name",
                "name",
                "sub"
        };

        for (String claimName : claimNames) {
            String value = jwt.getClaimAsString(claimName);
            if (isValidUsername(value)) {
                log.debug("Using {} as username: {}", claimName, value);
                return value;
            }
        }

        // Final fallback to subject
        return jwt.getSubject();
    }

    private static boolean isValidUsername(String username) {
        return username != null &&
                !username.trim().isEmpty() &&
                !username.equals("anonymousUser");
    }

    public static boolean isAdmin(Authentication authentication) {
        if (authentication == null) {
            return false;
        }

        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority ->
                        authority.equals("ROLE_ADMIN") ||
                                authority.equals("ADMIN") ||
                                authority.equals("ROLE_ADMINISTRATOR")
                );
    }
}