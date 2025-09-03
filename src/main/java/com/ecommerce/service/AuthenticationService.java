package com.ecommerce.service;

import com.ecommerce.dto.AuthenticationDTO;
import com.ecommerce.exception.CustomBusinessException;

public interface AuthenticationService {

    /**
     * Authenticates user and returns JWT token
     * @param loginRequest login credentials
     * @return login response with token
     * @throws CustomBusinessException if authentication fails
     */
    AuthenticationDTO.LoginResponse login(AuthenticationDTO.LoginRequest loginRequest) throws CustomBusinessException;

    /**
     * Validates JWT token
     * @param token JWT token to validate
     * @return token validation response
     * @throws CustomBusinessException if token is invalid
     */
    AuthenticationDTO.TokenValidationResponse validateToken(String token) throws CustomBusinessException;

    /**
     * Logs out user (invalidates token)
     * @param token JWT token to invalidate
     * @throws CustomBusinessException if logout fails
     */
    void logout(String token) throws CustomBusinessException;
}