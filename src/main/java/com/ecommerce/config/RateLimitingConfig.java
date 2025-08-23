package com.ecommerce.config;

import com.ecommerce.filter.RateLimitingFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.beans.factory.annotation.Value;

@Configuration
public class RateLimitingConfig {

    @Value("${ratelimit.capacity:100}")
    private int capacity;

    @Value("${ratelimit.refill-tokens:10}")
    private int refillTokens;

    @Value("${ratelimit.refill-duration-seconds:1}")
    private int refillDurationSeconds;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public RateLimitingFilter rateLimitingFilter() {
        return new RateLimitingFilter(capacity, refillTokens, refillDurationSeconds);
    }
}
