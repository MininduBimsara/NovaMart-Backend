package com.ecommerce.service.impl;

import com.ecommerce.domain.User;
import com.ecommerce.dto.AuthenticationDTO;
import com.ecommerce.exception.CustomBusinessException;
import com.ecommerce.repository.UserRepository;
import com.ecommerce.service.AuthenticationService;
import com.ecommerce.service.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;

    @Override
    public AuthenticationDTO.LoginResponse login(AuthenticationDTO.LoginRequest loginRequest) throws CustomBusinessException {
        // Find user by username or email
        Optional<User> userOpt = userRepository.findByUsernameOrEmailIgnoreCase(loginRequest.getUsername());

        if (userOpt.isEmpty()) {
            throw new CustomBusinessException("Invalid username or password");
        }

        User user = userOpt.get();

        // Verify password
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new CustomBusinessException("Invalid username or password");
        }

        // Generate JWT token
        String token = jwtTokenService.generateToken(user.getUsername(), user.getEmail(), user.getRoles());

        return AuthenticationDTO.LoginResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .username(user.getUsername())
                .email(user.getEmail())
                .name(user.getName())
                .roles(user.getRoles())
                .expiresIn(86400L) // 24 hours in seconds
                .build();
    }

    @Override
    public AuthenticationDTO.TokenValidationResponse validateToken(String token) throws CustomBusinessException {
        try {
            if (!jwtTokenService.validateToken(token)) {
                throw new CustomBusinessException("Invalid or expired token");
            }

            String username = jwtTokenService.extractUsername(token);
            String email = jwtTokenService.extractEmail(token);
            var roles = jwtTokenService.extractRoles(token);

            return AuthenticationDTO.TokenValidationResponse.builder()
                    .valid(true)
                    .username(username)
                    .email(email)
                    .roles(roles)
                    .expiresAt(jwtTokenService.extractExpiration(token).toInstant())
                    .build();

        } catch (Exception e) {
            throw new CustomBusinessException("Token validation failed: " + e.getMessage());
        }
    }

    @Override
    public void logout(String token) throws CustomBusinessException {
        // In a production environment, you might want to blacklist the token
        // For now, we'll just validate that the token exists and is valid
        if (!jwtTokenService.validateToken(token)) {
            throw new CustomBusinessException("Invalid token for logout");
        }
        // Token will naturally expire, or you could implement a blacklist mechanism
    }
}