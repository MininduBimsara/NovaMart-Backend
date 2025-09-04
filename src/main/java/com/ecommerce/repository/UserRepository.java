package com.ecommerce.repository;

import com.ecommerce.domain.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User, String> {

    /**
     * Find user by username
     */
    Optional<User> findByUsername(String username);

    /**
     * Find user by email (case insensitive)
     */
    @Query("{'email': {$regex: ?0, $options: 'i'}}")
    Optional<User> findByEmailIgnoreCase(String email);

    /**
     * Find user by username or email (case insensitive)
     */
    @Query("{ $or: [ {'username': ?0}, {'email': ?0} ] }")
    Optional<User> findByUsernameOrEmailIgnoreCase(String usernameOrEmail);

    /**
     * Check if username exists
     */
    boolean existsByUsername(String username);

    /**
     * Check if email exists (case insensitive)
     */
    @Query(value = "{'email': {$regex: ?0, $options: 'i'}}", exists = true)
    boolean existsByEmailIgnoreCase(String email);
}