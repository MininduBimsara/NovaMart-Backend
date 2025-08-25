package com.ecommerce.domain;

import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.time.LocalDate;

@Document(collection = "purchases")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Purchase {
    @Id
    private String id;

    private String username; // From JWT token
    private LocalDate purchaseDate; // Must be today or future, not Sunday
    private String deliveryTime; // 10AM, 11AM, 12PM
    private String deliveryLocation; // Sri Lankan district
    private String productName; // From predefined list
    private Integer quantity;
    private String message; // Optional message
    private String status; // PENDING, CONFIRMED, DELIVERED, etc.

    @CreatedDate
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;
}