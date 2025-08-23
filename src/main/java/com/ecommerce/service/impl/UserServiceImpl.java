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

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDTO registerUser(@Valid UserDTO userDTO) throws CustomBusinessException {
        if (userRepository.findByUsername(userDTO.getUsername()).isPresent()) {
            throw new CustomBusinessException("Username already exists");
        }
        if (userRepository.findAll().stream()
                .anyMatch(user -> user.getEmail().equalsIgnoreCase(userDTO.getEmail()))) {
            throw new CustomBusinessException("Email already exists");
        }

        User user = MapperUtil.toUser(userDTO);
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.setRoles(Set.of("ROLE_USER"));
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
}
