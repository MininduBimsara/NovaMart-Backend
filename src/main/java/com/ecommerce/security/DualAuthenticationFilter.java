package com.ecommerce.security;

import com.ecommerce.service.impl.JwtTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Enhanced Dual Authentication Filter supporting both Local JWT (HS256) and Asgardeo OAuth2 JWT (RS256)
 */

@Slf4j
@Component
@RequiredArgsConstructor
public class DualAuthenticationFilter extends OncePerRequestFilter {

    /**
     * Token types supported by this filter
     */
    private enum TokenType {
        LOCAL_HS256,
        ASGARDEO_RS256,
        UNKNOWN
    }

    private final JwtTokenService jwtTokenService;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}")
    private String jwkSetUri;

    @Value("${asgardeo.org-name:}")
    private String asgardeoOrgName;

    private JwtDecoder jwtDecoder; // Will be created lazily

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String requestURI = request.getRequestURI();
        final String method = request.getMethod();
        final String authHeader = request.getHeader("Authorization");

        log.debug("=== DUAL AUTH FILTER ===");
        log.debug("Request: {} {}", method, requestURI);
        log.debug("Auth header present: {}", authHeader != null);

        // Skip if no Authorization header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("No Bearer token found, continuing filter chain");
            filterChain.doFilter(request, response);
            return;
        }

        // Skip if already authenticated
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            log.debug("Already authenticated, skipping");
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);
        log.debug("Extracted token, length: {}", token.length());

        try {
            // Determine token type and authenticate accordingly
            TokenType tokenType = determineTokenType(token);
            log.info("Detected token type: {}", tokenType);

            switch (tokenType) {
                case ASGARDEO_RS256:
                    authenticateAsgardeoToken(token, request);
                    break;
                case LOCAL_HS256:
                    authenticateLocalToken(token, request);
                    break;
                case UNKNOWN:
                default:
                    log.warn("Unknown token type, authentication failed");
                    break;
            }
        } catch (Exception e) {
            log.error("Authentication failed: {}", e.getMessage(), e);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private JwtDecoder getJwtDecoder() {
        if (jwtDecoder == null && isOAuth2Configured()) {
            try {
                log.info("Creating JwtDecoder with JWK Set URI: {}", jwkSetUri);
                jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
            } catch (Exception e) {
                log.error("Failed to create JwtDecoder: {}", e.getMessage());
                jwtDecoder = null;
            }
        }
        return jwtDecoder;
    }

    private boolean isOAuth2Configured() {
        return jwkSetUri != null && !jwkSetUri.isEmpty() && 
               asgardeoOrgName != null && !asgardeoOrgName.isEmpty();
    }

    /**
     * Enhanced token type determination with better error handling
     */
    private TokenType determineTokenType(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                log.debug("Invalid JWT format - not 3 parts");
                return TokenType.UNKNOWN;
            }

            // Decode header to check algorithm
            byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
            String headerJson = new String(headerBytes);
            log.debug("JWT header: {}", headerJson);

            // Check algorithm type
            if (headerJson.contains("\"alg\":\"RS256\"")) {
                log.debug("Detected RS256 algorithm - Asgardeo token");
                return TokenType.ASGARDEO_RS256;
            } else if (headerJson.contains("\"alg\":\"HS256\"")) {
                log.debug("Detected HS256 algorithm - Local token");
                return TokenType.LOCAL_HS256;
            } else {
                log.debug("Unknown algorithm in token header");
                return TokenType.UNKNOWN;
            }
        } catch (Exception e) {
            log.debug("Error determining token type: {}", e.getMessage());
            return TokenType.UNKNOWN;
        }
    }

    /**
     * Enhanced Asgardeo token authentication with better error handling
     */
    private void authenticateAsgardeoToken(String token, HttpServletRequest request) {
        if (!isOAuth2Configured()) {
            log.warn("Asgardeo OAuth2 not configured - missing org name or JWKS URI");
            return;
        }

        JwtDecoder decoder = getJwtDecoder();
        if (decoder == null) {
            log.warn("JwtDecoder not available for Asgardeo token - check JWKS URI configuration");
            return;
        }

        try {
            log.debug("Attempting to decode Asgardeo JWT token");
            Jwt jwt = decoder.decode(token);
            log.debug("JWT decoded successfully. Claims: {}", jwt.getClaims().keySet());

            // Extract username with multiple fallbacks
            String username = extractUsernameFromAsgardeoJwt(jwt);
            if (username == null || username.trim().isEmpty()) {
                log.error("Could not extract username from Asgardeo JWT");
                return;
            }

            // Extract authorities with enhanced logic
            Collection<SimpleGrantedAuthority> authorities = extractAuthoritiesFromAsgardeoJwt(jwt);
            log.debug("Extracted authorities: {}", authorities);

            // Create authentication token
            JwtAuthenticationToken authToken = new JwtAuthenticationToken(jwt, authorities, username);
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authToken);
            log.info("✅ Asgardeo authentication successful for user: {} with authorities: {}", username, authorities);

        } catch (JwtException e) {
            log.error("❌ Asgardeo JWT validation failed: {}", e.getMessage());
        } catch (Exception e) {
            log.error("❌ Unexpected error during Asgardeo authentication: {}", e.getMessage(), e);
        }
    }

    /**
     * Enhanced local token authentication with better error handling
     */
    private void authenticateLocalToken(String token, HttpServletRequest request) {
        try {
            log.debug("Attempting to authenticate local JWT token");
            String username = jwtTokenService.extractUsername(token);
            
            if (username == null || username.trim().isEmpty()) {
                log.error("Could not extract username from local JWT");
                return;
            }

            if (jwtTokenService.validateToken(token, username)) {
                Set<String> roles = jwtTokenService.extractRoles(token);
                log.debug("Extracted roles from local JWT: {}", roles);

                var authorities = roles.stream()
                        .map(role -> {
                            String authority = role.toUpperCase();
                            if (!authority.startsWith("ROLE_")) {
                                authority = "ROLE_" + authority;
                            }
                            return new SimpleGrantedAuthority(authority);
                        })
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        username, null, authorities
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
                log.info("✅ Local JWT authentication successful for user: {} with authorities: {}", username, authorities);
            } else {
                log.warn("❌ Local JWT token validation failed for user: {}", username);
            }
        } catch (Exception e) {
            log.error("❌ Local token authentication failed: {}", e.getMessage(), e);
        }
    }

    /**
     * Enhanced username extraction from Asgardeo JWT with multiple fallbacks
     */
    private String extractUsernameFromAsgardeoJwt(Jwt jwt) {
        // Try multiple claim names in order of preference
        String username = jwt.getClaimAsString("preferred_username");
        if (username == null || username.trim().isEmpty()) {
            username = jwt.getClaimAsString("email");
        }
        if (username == null || username.trim().isEmpty()) {
            username = jwt.getClaimAsString("username");
        }
        if (username == null || username.trim().isEmpty()) {
            username = jwt.getClaimAsString("upn"); // User Principal Name
        }
        if (username == null || username.trim().isEmpty()) {
            username = jwt.getSubject();
        }
        
        log.debug("Extracted username from Asgardeo JWT: {}", username);
        return username;
    }

    /**
     * Enhanced authority extraction from Asgardeo JWT with comprehensive role mapping
     */
    private Collection<SimpleGrantedAuthority> extractAuthoritiesFromAsgardeoJwt(Jwt jwt) {
        Set<String> roles = new HashSet<>();

        // Check multiple possible role claims (Asgardeo specific)
        Object groupsObj = jwt.getClaim("groups");
        if (groupsObj instanceof List<?>) {
            ((List<?>) groupsObj).forEach(group -> {
                String groupStr = group.toString();
                log.debug("Found group: {}", groupStr);
                roles.add(groupStr);
            });
        }

        Object rolesObj = jwt.getClaim("roles");
        if (rolesObj instanceof List<?>) {
            ((List<?>) rolesObj).forEach(role -> {
                String roleStr = role.toString();
                log.debug("Found role: {}", roleStr);
                roles.add(roleStr);
            });
        }

        // Check for application-specific roles
        Object appRolesObj = jwt.getClaim("application_roles");
        if (appRolesObj instanceof List<?>) {
            ((List<?>) appRolesObj).forEach(role -> {
                String roleStr = role.toString();
                log.debug("Found application role: {}", roleStr);
                roles.add(roleStr);
            });
        }

        // Check for scopes (OAuth2 standard)
        String scope = jwt.getClaimAsString("scope");
        if (scope != null && !scope.trim().isEmpty()) {
            Arrays.stream(scope.split("\\s+"))
                    .filter(s -> !s.trim().isEmpty())
                    .forEach(s -> {
                        log.debug("Found scope: {}", s);
                        roles.add("SCOPE_" + s.toUpperCase());
                    });
        }

        // Check for authorities claim
        Object authoritiesObj = jwt.getClaim("authorities");
        if (authoritiesObj instanceof List<?>) {
            ((List<?>) authoritiesObj).forEach(authority -> {
                String authStr = authority.toString();
                log.debug("Found authority: {}", authStr);
                roles.add(authStr);
            });
        }

        // Default role if no roles found
        if (roles.isEmpty()) {
            log.debug("No roles found in JWT, assigning default USER role");
            roles.add("USER");
        }

        // Convert to Spring Security authorities
        return roles.stream()
                .map(role -> {
                    String authority = role.toUpperCase();
                    // Don't add ROLE_ prefix if it already has ROLE_ or SCOPE_
                    if (!authority.startsWith("ROLE_") && !authority.startsWith("SCOPE_")) {
                        authority = "ROLE_" + authority;
                    }
                    return new SimpleGrantedAuthority(authority);
                })
                .collect(Collectors.toList());
    }
}