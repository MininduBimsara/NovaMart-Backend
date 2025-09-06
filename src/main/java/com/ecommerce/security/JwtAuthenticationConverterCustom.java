// src/main/java/com/ecommerce/security/JwtAuthenticationConverterCustom.java
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
        log.info("=== ASGARDEO JWT CONVERSION ===");
        log.info("JWT subject: {}", jwt.getSubject());
        log.info("JWT claims: {}", jwt.getClaims().keySet());
        log.info("Available claims: {}", jwt.getClaims());

        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        log.info("Final authorities for Asgardeo JWT: {}", authorities);
        log.info("=== END JWT CONVERSION ===");

        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Extract authorities from JWT claims
        Collection<String> roles = extractRolesFromJwt(jwt);
        Collection<String> scopes = extractScopesFromJwt(jwt);

        log.info("Extracted roles: {}", roles);
        log.info("Extracted scopes: {}", scopes);

        // Combine roles and scopes
        return Stream.concat(
                roles.stream().map(role -> {
                    String authority = "ROLE_" + role.toUpperCase();
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
        log.info("=== EXTRACTING ROLES FROM ASGARDEO JWT ===");

        // 1. PRIORITY: Check for 'groups' claim first (Asgardeo's primary mechanism)
        if (jwt.hasClaim("groups")) {
            Object groups = jwt.getClaim("groups");
            log.info("Found 'groups' claim: {} (type: {})", groups, groups != null ? groups.getClass().getSimpleName() : "null");

            if (groups instanceof List<?> groupList) {
                List<String> roleList = groupList.stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
                log.info("Converted groups to roles: {}", roleList);

                // If groups exist, use them as roles
                if (!roleList.isEmpty()) {
                    return roleList;
                }
            } else if (groups instanceof String groupsStr) {
                log.info("Groups as string: {}", groupsStr);
                if (!groupsStr.trim().isEmpty()) {
                    return List.of(groupsStr.split("[\\s,]+"));
                }
            }
        }

        // 2. Check for 'roles' claim (if configured in Asgardeo)
        if (jwt.hasClaim("roles")) {
            Object roles = jwt.getClaim("roles");
            log.info("Found 'roles' claim: {} (type: {})", roles, roles != null ? roles.getClass().getSimpleName() : "null");

            if (roles instanceof List<?> rolesList) {
                List<String> roleList = rolesList.stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
                log.info("Using roles from 'roles' claim: {}", roleList);
                if (!roleList.isEmpty()) {
                    return roleList;
                }
            } else if (roles instanceof String rolesStr) {
                log.info("Roles as string: {}", rolesStr);
                if (!rolesStr.trim().isEmpty()) {
                    return List.of(rolesStr.split("[\\s,]+"));
                }
            }
        }

        // 3. Check for 'application_roles' claim (custom roles)
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
            } else if (appRoles instanceof String appRolesStr) {
                if (!appRolesStr.trim().isEmpty()) {
                    return List.of(appRolesStr.split("[\\s,]+"));
                }
            }
        }

        // 4. CRITICAL: Default for all authenticated Asgardeo users
        log.info("No roles/groups found in JWT, assigning default USER role for authenticated Asgardeo user");
        return Collections.singletonList("USER");
    }

    @SuppressWarnings("unchecked")
    private Collection<String> extractScopesFromJwt(Jwt jwt) {
        log.debug("=== EXTRACTING SCOPES ===");

        // Extract scopes from 'scope' claim
        if (jwt.hasClaim("scope")) {
            String scopeString = jwt.getClaimAsString("scope");
            if (scopeString != null && !scopeString.trim().isEmpty()) {
                List<String> scopes = List.of(scopeString.split("\\s+"));
                log.debug("Extracted scopes from 'scope' claim: {}", scopes);
                return scopes;
            }
        }

        // Extract from 'scp' claim (some providers use this)
        if (jwt.hasClaim("scp")) {
            Object scp = jwt.getClaim("scp");
            if (scp instanceof List<?> scpList) {
                List<String> scopes = scpList.stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
                log.debug("Extracted scopes from 'scp' claim: {}", scopes);
                return scopes;
            } else if (scp instanceof String scpStr) {
                List<String> scopes = List.of(scpStr.split("\\s+"));
                log.debug("Extracted scopes from 'scp' string: {}", scopes);
                return scopes;
            }
        }

        log.debug("No scopes found in JWT");
        return Collections.emptyList();
    }
}