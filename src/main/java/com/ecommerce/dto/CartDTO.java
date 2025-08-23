package com.ecommerce.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class CartDTO {

    @NotBlank(message = "User ID is mandatory")
    private String userId;

    @Valid
    @NotEmpty(message = "Cart must have at least one item")
    private List<CartItemDTO> items = new ArrayList<>();

    @Data
    public static class CartItemDTO {
        @NotBlank(message = "Product ID is mandatory")
        private String productId;

        @Min(value = 1, message = "Quantity must be at least 1")
        private int quantity;
    }
}
