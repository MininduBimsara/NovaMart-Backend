package com.ecommerce.security;

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

@Component
public class JwtAuthenticationConverterCustom implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Extract authorities from JWT claims
        // This implementation handles common OIDC/OAuth2 patterns

        // Try to get roles from different standard claims
        Collection<String> roles = extractRolesFromJwt(jwt);

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private Collection<String> extractRolesFromJwt(Jwt jwt) {
        // Try multiple common claim names for roles
        Object roles = null;

        // Check for 'roles' claim (common in Auth0, Asgardeo)
        if (jwt.hasClaim("roles")) {
            roles = jwt.getClaim("roles");
        }
        // Check for 'authorities' claim
        else if (jwt.hasClaim("authorities")) {
            roles = jwt.getClaim("authorities");
        }
        // Check for 'groups' claim (common in some IDPs)
        else if (jwt.hasClaim("groups")) {
            roles = jwt.getClaim("groups");
        }
        // Check for scope claim and convert to roles
        else if (jwt.hasClaim("scope")) {
            String scope = jwt.getClaimAsString("scope");
            if (scope != null) {
                return List.of(scope.split(" "));
            }
        }

        if (roles instanceof List<?>) {
            return ((List<?>) roles).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
        } else if (roles instanceof String) {
            // Handle space or comma-separated roles
            return List.of(roles.toString().split("[\\s,]+"));
        }

        // Default role if no roles found
        return Collections.singletonList("USER");
    }
}