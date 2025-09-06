// src/main/java/com/ecommerce/security/JwtAuthenticationFilter.java - FIXED VERSION
package com.ecommerce.security;

import com.ecommerce.service.impl.JwtTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // Check if Authorization header exists and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7); // Remove "Bearer " prefix

        try {
            // FIX: Only process tokens that look like local JWT tokens
            if (!isLocalJwtToken(jwt)) {
                System.out.println("[JwtAuthenticationFilter] Skipping non-local JWT token (likely Asgardeo)");
                filterChain.doFilter(request, response);
                return;
            }

            username = jwtTokenService.extractUsername(jwt);
            System.out.println("=== LOCAL JWT FILTER DEBUG ===");
            System.out.println("JWT Token type: LOCAL");
            System.out.println("Extracted username: " + username);

            // If username is extracted and no authentication exists in context
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Validate the token
                if (jwtTokenService.validateToken(jwt, username)) {
                    // Extract roles from JWT
                    Set<String> roles = jwtTokenService.extractRoles(jwt);
                    System.out.println("Extracted roles: " + roles);

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

                    System.out.println("Final authorities: " + authorities);

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

                    System.out.println("Local JWT authentication set successfully in SecurityContext");
                } else {
                    System.out.println("Local JWT token validation failed for user: " + username);
                }
            } else if (username == null) {
                System.out.println("Could not extract username from local JWT token");
            } else {
                System.out.println("Authentication already exists in SecurityContext");
            }
            System.out.println("=== END LOCAL JWT FILTER DEBUG ===");
        } catch (Exception e) {
            // Log the error but don't block the filter chain
            System.err.println("Local JWT Authentication failed: " + e.getMessage());
            // Don't print full stack trace for expected errors (like Asgardeo tokens)
            if (!e.getMessage().contains("RS256") && !e.getMessage().contains("unsupported")) {
                e.printStackTrace();
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Determine if this is a local JWT token (created by our JwtTokenService)
     * vs an external token like Asgardeo
     */
    private boolean isLocalJwtToken(String token) {
        try {
            // Quick check: decode the header to see the algorithm
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }

            // Decode header (first part)
            byte[] headerBytes = java.util.Base64.getUrlDecoder().decode(parts[0]);
            String headerJson = new String(headerBytes);

            System.out.println("[JwtAuthenticationFilter] Token header: " + headerJson);

            // Local tokens use HS256, Asgardeo uses RS256
            boolean isLocal = headerJson.contains("\"alg\":\"HS256\"");
            System.out.println("[JwtAuthenticationFilter] Is local token: " + isLocal);

            return isLocal;
        } catch (Exception e) {
            System.out.println("[JwtAuthenticationFilter] Could not determine token type, assuming external: " + e.getMessage());
            return false; // If we can't determine, assume it's external (Asgardeo)
        }
    }
}