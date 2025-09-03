package com.ecommerce.config;

import com.ecommerce.service.impl.UserServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class ApplicationStartupConfig {

    private final UserServiceImpl userService;

    @Bean
    public ApplicationRunner initializeApplication() {
        return args -> {
            log.info("Initializing application...");

            // Create default admin user if none exists
            try {
                userService.createDefaultAdminIfNotExists();
                log.info("Admin user initialization completed");
            } catch (Exception e) {
                log.error("Failed to initialize admin user: {}", e.getMessage());
            }

            log.info("Application initialization completed");
        };
    }
}