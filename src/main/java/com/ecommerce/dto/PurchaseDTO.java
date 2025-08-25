package com.ecommerce.dto;

import com.ecommerce.validation.ValidDeliveryDate;
import jakarta.validation.constraints.*;
import lombok.Data;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PurchaseDTO {

    private String id;

    @NotBlank(message = "Username is mandatory")
    private String username;

    @NotNull(message = "Purchase date is mandatory")
    @ValidDeliveryDate
    private LocalDate purchaseDate;

    @NotBlank(message = "Delivery time is mandatory")
    @Pattern(regexp = "10AM|11AM|12PM", message = "Delivery time must be 10AM, 11AM, or 12PM")
    private String deliveryTime;

    @NotBlank(message = "Delivery location is mandatory")
    private String deliveryLocation;

    @NotBlank(message = "Product name is mandatory")
    private String productName;

    @NotNull(message = "Quantity is mandatory")
    @Min(value = 1, message = "Quantity must be at least 1")
    @Max(value = 100, message = "Quantity cannot exceed 100")
    private Integer quantity;

    @Size(max = 500, message = "Message cannot exceed 500 characters")
    private String message;

    private String status;
}