// src/main/java/com/ecommerce/controller/DebugController.java
package com.ecommerce.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/debug")
@Tag(name = "Debug", description = "Debug endpoints for JWT testing")
@Slf4j
public class DebugController {

    @GetMapping("/auth-info")
    @Operation(summary = "Get authentication information", description = "Returns current authentication details")
    public ResponseEntity<Map<String, Object>> getAuthInfo(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        Map<String, Object> response = new HashMap<>();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        response.put("hasAuthentication", authentication != null);
        response.put("authorizationHeader", authHeader != null ? "Present (Bearer ...)" : "Missing");

        if (authentication != null) {
            response.put("authType", authentication.getClass().getSimpleName());
            response.put("principal", authentication.getName());
            response.put("authorities", authentication.getAuthorities().stream()
                    .map(auth -> auth.getAuthority())
                    .toList());
            response.put("isAuthenticated", authentication.isAuthenticated());

            // If it's a JWT token, extract additional info
            if (authentication instanceof JwtAuthenticationToken jwtAuth) {
                Jwt jwt = jwtAuth.getToken();
                Map<String, Object> jwtInfo = new HashMap<>();
                jwtInfo.put("subject", jwt.getSubject());
                jwtInfo.put("issuer", jwt.getIssuer());
                jwtInfo.put("audience", jwt.getAudience());
                jwtInfo.put("expiresAt", jwt.getExpiresAt());
                jwtInfo.put("issuedAt", jwt.getIssuedAt());

                // Extract common claims
                Map<String, Object> claims = new HashMap<>();
                claims.put("email", jwt.getClaimAsString("email"));
                claims.put("preferred_username", jwt.getClaimAsString("preferred_username"));
                claims.put("given_name", jwt.getClaimAsString("given_name"));
                claims.put("family_name", jwt.getClaimAsString("family_name"));
                claims.put("name", jwt.getClaimAsString("name"));
                claims.put("groups", jwt.getClaim("groups"));
                claims.put("roles", jwt.getClaim("roles"));
                claims.put("scope", jwt.getClaimAsString("scope"));

                jwtInfo.put("claims", claims);
                response.put("jwtInfo", jwtInfo);
            }
        }

        log.debug("Auth info request: {}", response);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/token-test")
    @Operation(summary = "Test JWT token parsing", description = "Tests if the current token can be parsed correctly")
    public ResponseEntity<Map<String, Object>> testToken() {
        Map<String, Object> response = new HashMap<>();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            response.put("error", "No authentication found");
            response.put("message", "Please provide a valid JWT token in the Authorization header");
            return ResponseEntity.ok(response);
        }

        response.put("success", true);
        response.put("message", "Token parsed successfully");
        response.put("authenticationType", authentication.getClass().getSimpleName());
        response.put("username", authentication.getName());
        response.put("roles", authentication.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .toList());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    @Operation(summary = "Health check", description = "Simple health check endpoint")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "E-Commerce Backend Debug");
        response.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(response);
    }
}