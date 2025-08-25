package com.ecommerce.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.EnableMongoAuditing;

@Configuration
@EnableMongoAuditing
public class MongoConfig {
    // This enables @CreatedDate and @LastModifiedDate annotations in MongoDB entities
}