// src/main/java/com/ecommerce/security/JwtAuthenticationConverterCustom.java - FIXED
package com.ecommerce.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Component
public class JwtAuthenticationConverterCustom implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        log.info("=== CONVERTING ASGARDEO JWT ===");
        log.info("JWT subject: {}", jwt.getSubject());
        log.info("JWT issuer: {}", jwt.getIssuer());
        log.info("JWT claims: {}", jwt.getClaims().keySet());

        // Debug all claims for troubleshooting
        jwt.getClaims().forEach((key, value) -> {
            log.debug("Claim [{}]: {}", key, value);
        });

        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        log.info("Final authorities for Asgardeo JWT: {}", authorities);
        log.info("=== END JWT CONVERSION ===");

        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Collection<String> roles = extractRolesFromJwt(jwt);
        Collection<String> scopes = extractScopesFromJwt(jwt);

        log.info("Extracted roles: {}", roles);
        log.info("Extracted scopes: {}", scopes);

        // Combine roles and scopes into authorities
        return Stream.concat(
                roles.stream().map(role -> {
                    // Ensure ROLE_ prefix for Spring Security
                    String authority = role.toUpperCase().startsWith("ROLE_") ?
                            role.toUpperCase() : "ROLE_" + role.toUpperCase();
                    log.debug("Creating role authority: {}", authority);
                    return new SimpleGrantedAuthority(authority);
                }),
                scopes.stream().map(scope -> {
                    String authority = "SCOPE_" + scope.toUpperCase();
                    log.debug("Creating scope authority: {}", authority);
                    return new SimpleGrantedAuthority(authority);
                })
        ).collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private Collection<String> extractRolesFromJwt(Jwt jwt) {
        log.debug("=== EXTRACTING ROLES FROM ASGARDEO JWT ===");

        // PRIORITY 1: Check for 'groups' claim (Asgardeo's primary mechanism)
        if (jwt.hasClaim("groups")) {
            Object groups = jwt.getClaim("groups");
            log.info("Found 'groups' claim: {} (type: {})", groups,
                    groups != null ? groups.getClass().getSimpleName() : "null");

            if (groups instanceof List<?> groupList) {
                List<String> roleList = groupList.stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
                log.info("Using groups as roles: {}", roleList);
                if (!roleList.isEmpty()) {
                    return roleList;
                }
            } else if (groups instanceof String groupsStr) {
                if (!groupsStr.trim().isEmpty()) {
                    List<String> roles = List.of(groupsStr.split("[\\s,]+"));
                    log.info("Using groups string as roles: {}", roles);
                    return roles;
                }
            }
        }

        // PRIORITY 2: Check for 'roles' claim
        if (jwt.hasClaim("roles")) {
            Object roles = jwt.getClaim("roles");
            log.info("Found 'roles' claim: {}", roles);

            if (roles instanceof List<?> rolesList) {
                List<String> roleList = rolesList.stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
                if (!roleList.isEmpty()) {
                    return roleList;
                }
            } else if (roles instanceof String rolesStr) {
                if (!rolesStr.trim().isEmpty()) {
                    return List.of(rolesStr.split("[\\s,]+"));
                }
            }
        }

        // PRIORITY 3: Check for custom application roles
        if (jwt.hasClaim("application_roles")) {
            Object appRoles = jwt.getClaim("application_roles");
            log.info("Found 'application_roles' claim: {}", appRoles);

            if (appRoles instanceof List<?> appRolesList) {
                List<String> roleList = appRolesList.stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
                if (!roleList.isEmpty()) {
                    return roleList;
                }
            }
        }

        // PRIORITY 4: Check if user has admin indicators in username/email
        String username = extractUsername(jwt);
        if (username != null && (username.toLowerCase().contains("admin") ||
                username.toLowerCase().equals("admin@ecommerce.com"))) {
            log.info("Detected admin user by username pattern: {}", username);
            return List.of("ADMIN", "USER");
        }

        // DEFAULT: All authenticated Asgardeo users get USER role
        log.info("No specific roles found, assigning default USER role");
        return Collections.singletonList("USER");
    }

    @SuppressWarnings("unchecked")
    private Collection<String> extractScopesFromJwt(Jwt jwt) {
        // Extract scopes from 'scope' claim
        if (jwt.hasClaim("scope")) {
            String scopeString = jwt.getClaimAsString("scope");
            if (scopeString != null && !scopeString.trim().isEmpty()) {
                List<String> scopes = List.of(scopeString.split("\\s+"));
                log.debug("Extracted scopes: {}", scopes);
                return scopes;
            }
        }

        return Collections.emptyList();
    }

    /**
     * Extract username with multiple fallback strategies for Asgardeo
     */
    private String extractUsername(Jwt jwt) {
        // Try preferred_username first (most common in OIDC)
        String username = jwt.getClaimAsString("preferred_username");
        if (username != null && !username.trim().isEmpty()) {
            return username;
        }

        // Try email as username
        username = jwt.getClaimAsString("email");
        if (username != null && !username.trim().isEmpty()) {
            return username;
        }

        // Try generic username claim
        username = jwt.getClaimAsString("username");
        if (username != null && !username.trim().isEmpty()) {
            return username;
        }

        // Fallback to subject
        return jwt.getSubject();
    }
}