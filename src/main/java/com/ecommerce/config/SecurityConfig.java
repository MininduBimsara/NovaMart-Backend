package com.ecommerce.config;

import com.ecommerce.security.JwtAuthenticationConverterCustom;
import com.ecommerce.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
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
                // Add JWT filter before UsernamePasswordAuthenticationFilter for local JWT tokens
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        // Configure OAuth2 resource server only if Asgardeo is configured
        if (isOAuth2Configured()) {
            http.oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwt -> jwt
                            .decoder(jwtDecoder())
                            .jwtAuthenticationConverter(jwtAuthenticationConverter)
                    )
            );
        }

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
        // Only create OAuth2 JWT decoder if properly configured
        if (!isOAuth2Configured()) {
            return null;
        }

        try {
            // Primary: Use the configured JWK Set URI
            return NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                    .build();
        } catch (Exception e) {
            try {
                // Fallback: Construct JWK Set URI from issuer URI
                if (issuerUri != null && !issuerUri.isEmpty() && !issuerUri.contains("YOUR_ORG_NAME")) {
                    String fallbackJwkSetUri = issuerUri.replace("/oauth2/token", "/oauth2/jwks");
                    return NimbusJwtDecoder.withJwkSetUri(fallbackJwkSetUri)
                            .build();
                }
                throw new RuntimeException("OAuth2 JWT configuration incomplete", e);
            } catch (Exception ex) {
                throw new RuntimeException("Failed to configure OAuth2 JWT decoder. Using local JWT authentication only.", ex);
            }
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
     * Check if OAuth2/Asgardeo is properly configured
     */
    private boolean isOAuth2Configured() {
        return jwkSetUri != null &&
                !jwkSetUri.isEmpty() &&
                !jwkSetUri.contains("YOUR_ORG_NAME") &&
                issuerUri != null &&
                !issuerUri.isEmpty() &&
                !issuerUri.contains("YOUR_ORG_NAME");
    }
}