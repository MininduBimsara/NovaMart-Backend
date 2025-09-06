// src/main/java/com/ecommerce/config/SecurityConfig.java - COMPREHENSIVE FIX
package com.ecommerce.config;

import com.ecommerce.security.JwtAuthenticationConverterCustom;
import com.ecommerce.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}")
    private String issuerUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}")
    private String jwkSetUri;

    @Value("${cors.allowed-origins:http://localhost:3000}")
    private String allowedOrigins;

    private final JwtAuthenticationConverterCustom jwtAuthenticationConverter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring Security Filter Chain");
        log.info("OAuth2 configured: {}", isOAuth2Configured());
        log.info("JWK Set URI: {}", jwkSetUri);
        log.info("Issuer URI: {}", issuerUri);

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints - no authentication required
                        .requestMatchers(
                                "/api/auth/login",
                                "/api/auth/logout",
                                "/api/auth/validate-token",
                                "/api/auth/login-url",
                                "/api/auth/config",
                                "/api/users/register",
                                "/api/products",
                                "/api/products/**",
                                "/api/purchases/options/**",
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/webjars/**",
                                "/actuator/**",
                                "/error"
                        ).permitAll()
                        // Admin endpoints - require ADMIN role
                        .requestMatchers(
                                "/api/admin/**",
                                "/api/purchases/admin/**"
                        ).hasRole("ADMIN")
                        // All other requests need authentication
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        // CRITICAL FIX: Add OAuth2 resource server BEFORE local JWT filter
        if (isOAuth2Configured()) {
            log.info("Configuring OAuth2 Resource Server with JWK Set URI: {}", jwkSetUri);
            http.oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwt -> jwt
                            .decoder(jwtDecoder())
                            .jwtAuthenticationConverter(jwtAuthenticationConverter)
                    )
            );
        } else {
            log.warn("OAuth2 not configured - using local JWT authentication only");
        }

        // Add local JWT filter AFTER OAuth2 resource server
        http.addFilterAfter(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // Security headers
        http.headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                        .policyDirectives("default-src 'self'; " +
                                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                                "style-src 'self' 'unsafe-inline'; " +
                                "img-src 'self' data: https:; " +
                                "connect-src 'self' https:")
                )
                .frameOptions(frame -> frame.deny())
                .httpStrictTransportSecurity(hsts -> hsts
                        .maxAgeInSeconds(31536000)
                        .includeSubDomains(true)
                )
        );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        if (!isOAuth2Configured()) {
            log.warn("OAuth2 not configured - JwtDecoder will not be available");
            return null;
        }

        try {
            log.info("Creating JwtDecoder with JWK Set URI: {}", jwkSetUri);

            // Create decoder without caching configuration (compatible with all Spring Security versions)
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                    .build();

            log.info("JwtDecoder created successfully");
            return decoder;

        } catch (Exception e) {
            log.error("Failed to create JwtDecoder with JWK Set URI: {}", jwkSetUri, e);

            // Fallback: try to construct JWK Set URI from issuer URI
            try {
                if (issuerUri != null && !issuerUri.isEmpty() && !issuerUri.contains("YOUR_ORG_NAME")) {
                    String fallbackJwkSetUri = issuerUri.replace("/oauth2/token", "/oauth2/jwks");
                    log.info("Trying fallback JWK Set URI: {}", fallbackJwkSetUri);

                    NimbusJwtDecoder fallbackDecoder = NimbusJwtDecoder.withJwkSetUri(fallbackJwkSetUri)
                            .build();

                    log.info("Fallback JwtDecoder created successfully");
                    return fallbackDecoder;
                }
            } catch (Exception ex) {
                log.error("Fallback JwtDecoder creation also failed", ex);
            }

            throw new RuntimeException("Failed to configure OAuth2 JWT decoder", e);
        }
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Enhanced OAuth2 configuration check
     */
    private boolean isOAuth2Configured() {
        boolean hasJwkSetUri = jwkSetUri != null &&
                !jwkSetUri.isEmpty() &&
                !jwkSetUri.contains("YOUR_ORG_NAME") &&
                !jwkSetUri.equals("https://api.asgardeo.io/t/YOUR_ORG_NAME/oauth2/jwks");

        boolean hasIssuerUri = issuerUri != null &&
                !issuerUri.isEmpty() &&
                !issuerUri.contains("YOUR_ORG_NAME") &&
                !issuerUri.equals("https://api.asgardeo.io/t/YOUR_ORG_NAME/oauth2/token");

        boolean configured = hasJwkSetUri && hasIssuerUri;

        log.debug("OAuth2 Configuration Check:");
        log.debug("- JWK Set URI valid: {} ({})", hasJwkSetUri, jwkSetUri);
        log.debug("- Issuer URI valid: {} ({})", hasIssuerUri, issuerUri);
        log.debug("- Overall configured: {}", configured);

        return configured;
    }
}