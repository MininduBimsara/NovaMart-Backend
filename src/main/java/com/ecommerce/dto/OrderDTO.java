package com.ecommerce.dto;

import com.ecommerce.validation.OrderStatus;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Data
public class OrderDTO {

    private String id;

    @NotBlank(message = "User ID is mandatory")
    private String userId;

    @Valid
    @NotEmpty(message = "Order must have at least one item")
    private List<OrderItemDTO> items = new ArrayList<>();

    @DecimalMin(value = "0.0", inclusive = true, message = "Total amount must be non-negative")
    private BigDecimal totalAmount;


    private OrderStatus status;

    @Data
    public static class OrderItemDTO {
        @NotBlank(message = "Product ID is mandatory")
        private String productId;

        @DecimalMin(value = "1", inclusive = true, message = "Quantity must be at least 1")
        private int quantity;

        @DecimalMin(value = "0.0", inclusive = true, message = "Unit price must be non-negative")
        private BigDecimal unitPrice;
    }
}
