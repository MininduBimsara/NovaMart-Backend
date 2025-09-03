package com.ecommerce.service.impl;

import com.ecommerce.domain.User;
import com.ecommerce.dto.UserDTO;
import com.ecommerce.exception.CustomBusinessException;
import com.ecommerce.repository.UserRepository;
import com.ecommerce.service.UserService;
import com.ecommerce.util.MapperUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDTO registerUser(@Valid UserDTO userDTO) throws CustomBusinessException {
        if (userRepository.existsByUsername(userDTO.getUsername())) {
            throw new CustomBusinessException("Username already exists");
        }
        if (userRepository.existsByEmailIgnoreCase(userDTO.getEmail())) {
            throw new CustomBusinessException("Email already exists");
        }

        User user = MapperUtil.toUser(userDTO);
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));

        // Set default role if none provided
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.setRoles(Set.of("USER"));
        }

        User savedUser = userRepository.save(user);
        return MapperUtil.toUserDTO(savedUser);
    }

    @Override
    public UserDTO getUserByUsername(String username) throws CustomBusinessException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new CustomBusinessException("User not found with username: " + username));
        return MapperUtil.toUserDTO(user);
    }

    @Override
    public UserDTO updateUser(String id, @Valid UserDTO userDTO) throws CustomBusinessException {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new CustomBusinessException("User not found with id: " + id));

        if (!user.getUsername().equals(userDTO.getUsername()) &&
                userRepository.findByUsername(userDTO.getUsername()).isPresent()) {
            throw new CustomBusinessException("Username already exists");
        }

        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        if (userDTO.getPassword() != null && !userDTO.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        }
        user.setRoles(userDTO.getRoles());
        user.setName(userDTO.getName());
        user.setContactNumber(userDTO.getContactNumber());
        user.setCountry(userDTO.getCountry());

        User updatedUser = userRepository.save(user);
        return MapperUtil.toUserDTO(updatedUser);
    }

    @Override
    public void deleteUser(String id) throws CustomBusinessException {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new CustomBusinessException("User not found with id: " + id));
        userRepository.delete(user);
    }

    /**
     * Check if the authenticated user is the owner of the resource
     * Used in @PreAuthorize annotations
     */
    public boolean isOwner(String resourceId, String authenticatedUsername) {
        try {
            User user = userRepository.findById(resourceId).orElse(null);
            return user != null && user.getUsername().equals(authenticatedUsername);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Create a default admin user if none exists
     * This method should be called during application startup
     */
    public void createDefaultAdminIfNotExists() {
        // Check if any admin user exists
        boolean adminExists = userRepository.findAll().stream()
                .anyMatch(user -> user.getRoles().contains("ADMIN"));

        if (!adminExists) {
            User adminUser = User.builder()
                    .username("admin")
                    .email("admin@ecommerce.com")
                    .password(passwordEncoder.encode("admin123"))
                    .name("System Administrator")
                    .roles(Set.of("ADMIN", "USER"))
                    .country("Sri Lanka")
                    .build();

            userRepository.save(adminUser);
            System.out.println("Default admin user created: username=admin, password=admin123");
        }
    }
}