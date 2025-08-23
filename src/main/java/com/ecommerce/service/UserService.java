package com.ecommerce.service;

import com.ecommerce.dto.UserDTO;
import com.ecommerce.exception.CustomBusinessException;
import jakarta.validation.Valid;

public interface UserService {
    /**
     * Registers a new user.
     * @param userDTO user data transfer object
     * @return registered user DTO
     * @throws CustomBusinessException if user already exists or validation fails
     */
    UserDTO registerUser(@Valid UserDTO userDTO) throws CustomBusinessException;

    /**
     * Retrieves user by username.
     * @param username username string
     * @return user DTO
     * @throws CustomBusinessException if user not found
     */
    UserDTO getUserByUsername(String username) throws CustomBusinessException;

    /**
     * Updates user information.
     * @param id user id
     * @param userDTO updated user data
     * @return updated user DTO
     * @throws CustomBusinessException if user not found or validation fails
     */
    UserDTO updateUser(String id, @Valid UserDTO userDTO) throws CustomBusinessException;

    /**
     * Deletes user by id.
     * @param id user id
     * @throws CustomBusinessException if user not found
     */
    void deleteUser(String id) throws CustomBusinessException;
}
