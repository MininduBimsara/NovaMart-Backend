// src/main/java/com/ecommerce/service/impl/JwtTokenService.java - FIXED VERSION
package com.ecommerce.service.impl;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtTokenService {

    @Value("${jwt.secret:mySecretKey1234567890123456789012345678901234567890}")
    private String jwtSecret;

    @Value("${jwt.expiration:86400000}") // 24 hours in milliseconds
    private Long jwtExpiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateToken(String username, String email, Set<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", email != null ? email : "");
        claims.put("username", username);
        claims.put("preferred_username", username);

        // FIX: Add roles in multiple formats for compatibility
        claims.put("roles", roles);
        claims.put("groups", roles); // For Asgardeo compatibility
        claims.put("authorities", roles.stream()
                .map(role -> "ROLE_" + role.toUpperCase())
                .collect(Collectors.toList()));

        claims.put("type", "LOCAL_JWT");

        return createToken(claims, username);
    }

    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractEmail(String token) {
        return extractClaim(token, claims -> {
            String email = claims.get("email", String.class);
            if (email == null || email.isEmpty()) {
                // Fallback to username if email not present
                return claims.getSubject();
            }
            return email;
        });
    }

    @SuppressWarnings("unchecked")
    public Set<String> extractRoles(String token) {
        return extractClaim(token, claims -> {
            Set<String> roles = new HashSet<>();

            // Try different role claim formats
            Object rolesObj = claims.get("roles");
            if (rolesObj instanceof List<?>) {
                ((List<?>) rolesObj).forEach(role -> {
                    String roleStr = role.toString();
                    // Remove ROLE_ prefix if present
                    if (roleStr.startsWith("ROLE_")) {
                        roleStr = roleStr.substring(5);
                    }
                    roles.add(roleStr.toUpperCase());
                });
            }

            // Try 'groups' claim (Asgardeo format)
            Object groupsObj = claims.get("groups");
            if (groupsObj instanceof List<?>) {
                ((List<?>) groupsObj).forEach(group -> {
                    String groupStr = group.toString();
                    if (groupStr.startsWith("ROLE_")) {
                        groupStr = groupStr.substring(5);
                    }
                    roles.add(groupStr.toUpperCase());
                });
            }

            // Try 'authorities' claim
            Object authoritiesObj = claims.get("authorities");
            if (authoritiesObj instanceof List<?>) {
                ((List<?>) authoritiesObj).forEach(authority -> {
                    String authStr = authority.toString();
                    if (authStr.startsWith("ROLE_")) {
                        authStr = authStr.substring(5);
                    }
                    roles.add(authStr.toUpperCase());
                });
            }

            // Default fallback
            if (roles.isEmpty()) {
                roles.add("USER");
            }

            return roles;
        });
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("JWT token is expired", e);
        } catch (UnsupportedJwtException e) {
            throw new RuntimeException("JWT token is unsupported", e);
        } catch (MalformedJwtException e) {
            throw new RuntimeException("JWT token is malformed", e);
        } catch (SecurityException e) {
            throw new RuntimeException("JWT signature validation failed", e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("JWT token compact of handler are invalid", e);
        }
    }

    public Boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            return true; // Consider expired if we can't parse
        }
    }

    public Boolean validateToken(String token, String username) {
        try {
            final String extractedUsername = extractUsername(token);
            return (extractedUsername.equals(username) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }

    public Boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }
}