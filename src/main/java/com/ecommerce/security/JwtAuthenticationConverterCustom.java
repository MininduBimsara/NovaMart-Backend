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
import java.util.stream.Stream;

@Component
public class JwtAuthenticationConverterCustom implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Extract authorities from JWT claims
        Collection<String> roles = extractRolesFromJwt(jwt);
        Collection<String> scopes = extractScopesFromJwt(jwt);

        // Combine roles and scopes
        return Stream.concat(
                roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())),
                scopes.stream().map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope.toUpperCase()))
        ).collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private Collection<String> extractRolesFromJwt(Jwt jwt) {
        Object roles = null;

        // Check for Asgardeo specific claims
        if (jwt.hasClaim("groups")) {
            roles = jwt.getClaim("groups");
        }
        // Check for standard 'roles' claim
        else if (jwt.hasClaim("roles")) {
            roles = jwt.getClaim("roles");
        }
        // Check for 'authorities' claim
        else if (jwt.hasClaim("authorities")) {
            roles = jwt.getClaim("authorities");
        }
        // Check for custom application roles
        else if (jwt.hasClaim("application_roles")) {
            roles = jwt.getClaim("application_roles");
        }

        if (roles instanceof List<?>) {
            return ((List<?>) roles).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
        } else if (roles instanceof String) {
            return List.of(roles.toString().split("[\\s,]+"));
        }

        // Default role based on token type or user existence
        return Collections.singletonList("USER");
    }

    @SuppressWarnings("unchecked")
    private Collection<String> extractScopesFromJwt(Jwt jwt) {
        // Extract scopes from 'scope' claim
        if (jwt.hasClaim("scope")) {
            String scopeString = jwt.getClaimAsString("scope");
            if (scopeString != null && !scopeString.trim().isEmpty()) {
                return List.of(scopeString.split("\\s+"));
            }
        }

        // Extract from 'scp' claim (some providers use this)
        if (jwt.hasClaim("scp")) {
            Object scp = jwt.getClaim("scp");
            if (scp instanceof List<?>) {
                return ((List<?>) scp).stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
            } else if (scp instanceof String) {
                return List.of(scp.toString().split("\\s+"));
            }
        }

        return Collections.emptyList();
    }
}