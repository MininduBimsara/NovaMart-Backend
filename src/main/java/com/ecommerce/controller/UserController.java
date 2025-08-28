package com.ecommerce.controller;

import com.ecommerce.dto.UserDTO;
import com.ecommerce.service.UserService;
import com.ecommerce.util.JwtUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "User registration and profile management")
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    @Operation(summary = "Register a new user", description = "Creates a new user account")
    public ResponseEntity<UserDTO> registerUser(@Valid @RequestBody UserDTO userDTO) {
        UserDTO registeredUser = userService.registerUser(userDTO);
        return new ResponseEntity<>(registeredUser, HttpStatus.CREATED);
    }

    @GetMapping("/profile")
    @Operation(summary = "Get user profile", description = "Returns authenticated user's profile information from JWT token")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<UserProfileResponse> getUserProfile(@AuthenticationPrincipal Jwt jwt) {
        UserProfileResponse profile = UserProfileResponse.builder()
                .username(JwtUtil.extractUsername(jwt))
                .name(JwtUtil.extractFullName(jwt))
                .email(JwtUtil.extractEmail(jwt))
                .contactNumber(JwtUtil.extractPhoneNumber(jwt))
                .country(JwtUtil.extractLocale(jwt))
                .roles(JwtUtil.extractRoles(jwt))
                .emailVerified(JwtUtil.isEmailVerified(jwt))
                .isAdmin(JwtUtil.isAdmin(jwt))
                .tokenExpiresAt(jwt.getExpiresAt())
                .timeToExpiry(JwtUtil.getTimeToExpiry(jwt))
                .build();

        return ResponseEntity.ok(profile);
    }

    @GetMapping("/profile/minimal")
    @Operation(summary = "Get minimal user profile", description = "Returns basic user information from JWT token")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<MinimalProfileResponse> getMinimalProfile(@AuthenticationPrincipal Jwt jwt) {
        MinimalProfileResponse profile = MinimalProfileResponse.builder()
                .username(JwtUtil.extractUsername(jwt))
                .name(JwtUtil.extractFullName(jwt))
                .email(JwtUtil.extractEmail(jwt))
                .isAdmin(JwtUtil.isAdmin(jwt))
                .build();

        return ResponseEntity.ok(profile);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update user", description = "Updates user information")
    @PreAuthorize("hasRole('ADMIN') or @userService.isOwner(#id, authentication.name)")
    public ResponseEntity<UserDTO> updateUser(@PathVariable String id, @Valid @RequestBody UserDTO userDTO) {
        UserDTO updatedUser = userService.updateUser(id, userDTO);
        return ResponseEntity.ok(updatedUser);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete user", description = "Deletes a user account")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/validate-token")
    @Operation(summary = "Validate current token", description = "Validates the current JWT token and returns basic info")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<TokenValidationResponse> validateToken(@AuthenticationPrincipal Jwt jwt) {
        TokenValidationResponse response = TokenValidationResponse.builder()
                .valid(!JwtUtil.isTokenExpired(jwt))
                .username(JwtUtil.extractUsername(jwt))
                .roles(JwtUtil.extractRoles(jwt))
                .timeToExpiry(JwtUtil.getTimeToExpiry(jwt))
                .build();

        return ResponseEntity.ok(response);
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserProfileResponse {
        private String username;
        private String name;
        private String email;
        private String contactNumber;
        private String country;
        private java.util.List<String> roles;
        private Boolean emailVerified;
        private Boolean isAdmin;
        private java.time.Instant tokenExpiresAt;
        private Long timeToExpiry;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MinimalProfileResponse {
        private String username;
        private String name;
        private String email;
        private Boolean isAdmin;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TokenValidationResponse {
        private Boolean valid;
        private String username;
        private java.util.List<String> roles;
        private Long timeToExpiry;
    }
}