// src/main/java/com/ecommerce/security/JwtAuthenticationFilter.java - DEBUG VERSION
package com.ecommerce.security;

import com.ecommerce.service.impl.JwtTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component; // Removed - not using @Component
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
// @Component - DISABLED: Using DualAuthenticationFilter instead
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String requestURI = request.getRequestURI();
        final String method = request.getMethod();
        final String authHeader = request.getHeader("Authorization");

        log.info("=== JWT FILTER DEBUG ===");
        log.info("Request: {} {}", method, requestURI);
        log.info("Auth header present: {}", authHeader != null);

        if (authHeader != null) {
            log.info("Auth header: {}", authHeader.substring(0, Math.min(authHeader.length(), 50)) + "...");
        }

        // Check if Authorization header exists and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("No Authorization header or doesn't start with Bearer");
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7); // Remove "Bearer " prefix
        log.info("JWT token extracted, length: {}", jwt.length());

        try {
            // Check if authentication already exists
            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                log.info("Authentication already exists, type: {}",
                        SecurityContextHolder.getContext().getAuthentication().getClass().getSimpleName());
                filterChain.doFilter(request, response);
                return;
            }

            // Check if this is a local JWT token (HS256) vs Asgardeo token (RS256)
            if (!isLocalJwtToken(jwt)) {
                log.info("Token is not a local JWT (likely Asgardeo RS256) - skipping local processing");
                filterChain.doFilter(request, response);
                return;
            }

            log.info("Processing local JWT token...");
            final String username = jwtTokenService.extractUsername(jwt);
            log.info("Extracted username from local JWT: {}", username);

            // Validate the local JWT token
            if (username != null && jwtTokenService.validateToken(jwt, username)) {
                log.info("Local JWT token is valid for user: {}", username);

                // Extract roles from JWT
                Set<String> roles = jwtTokenService.extractRoles(jwt);
                log.info("Extracted roles from local JWT: {}", roles);

                // Convert roles to authorities with ROLE_ prefix if not already present
                var authorities = roles.stream()
                        .map(role -> {
                            String authority = role.toUpperCase();
                            if (!authority.startsWith("ROLE_")) {
                                authority = "ROLE_" + authority;
                            }
                            return new SimpleGrantedAuthority(authority);
                        })
                        .collect(Collectors.toList());

                log.info("Final authorities for local JWT: {}", authorities);

                // Create authentication token with username as principal
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        username, // Use username string as principal
                        null, // No credentials needed for JWT
                        authorities
                );

                // Set additional details
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set authentication in security context
                SecurityContextHolder.getContext().setAuthentication(authToken);

                log.info("✅ Local JWT authentication successful for user: {} with authorities: {}", username, authorities);
            } else {
                log.warn("❌ Local JWT token validation failed for user: {}", username);
            }

        } catch (Exception e) {
            log.error("❌ Local JWT Authentication failed: {}", e.getMessage(), e);
            // Clear any partial authentication
            SecurityContextHolder.clearContext();
        }

        log.info("=== END JWT FILTER ===");
        filterChain.doFilter(request, response);
    }

    /**
     * Enhanced method to determine if this is a local JWT token (HS256)
     */
    private boolean isLocalJwtToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                log.debug("Token doesn't have 3 parts - not a valid JWT");
                return false;
            }

            // Decode header (first part)
            byte[] headerBytes = java.util.Base64.getUrlDecoder().decode(parts[0]);
            String headerJson = new String(headerBytes);
            log.debug("JWT header: {}", headerJson);

            // Local tokens use HS256, Asgardeo uses RS256
            boolean isLocal = headerJson.contains("\"alg\":\"HS256\"");
            log.debug("Token algorithm check - isLocal: {}", isLocal);

            return isLocal;
        } catch (Exception e) {
            log.debug("Could not determine token type, assuming external: {}", e.getMessage());
            return false;
        }
    }
}