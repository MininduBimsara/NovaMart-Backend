package com.ecommerce.util;

import com.ecommerce.domain.Cart;
import com.ecommerce.domain.Order;
import com.ecommerce.domain.Product;
import com.ecommerce.domain.User;
import com.ecommerce.dto.CartDTO;
import com.ecommerce.dto.OrderDTO;
import com.ecommerce.dto.ProductDTO;
import com.ecommerce.dto.UserDTO;

import java.util.stream.Collectors;

public class MapperUtil {

    // User mapping
    public static User toUser(UserDTO dto) {
        if (dto == null) return null;

        return User.builder()
                .id(dto.getId())
                .username(dto.getUsername())
                .email(dto.getEmail())
                .password(dto.getPassword())
                .roles(dto.getRoles())
                .name(dto.getName())
                .contactNumber(dto.getContactNumber())
                .country(dto.getCountry())
                .build();
    }

    public static UserDTO toUserDTO(User entity) {
        if (entity == null) return null;

        UserDTO dto = new UserDTO();
        dto.setId(entity.getId());
        dto.setUsername(entity.getUsername());
        dto.setEmail(entity.getEmail());
        // Don't expose password in DTO
        dto.setRoles(entity.getRoles());
        dto.setName(entity.getName());
        dto.setContactNumber(entity.getContactNumber());
        dto.setCountry(entity.getCountry());
        return dto;
    }

    // Product mapping
    public static Product toProduct(ProductDTO dto) {
        if (dto == null) return null;

        return Product.builder()
                .id(dto.getId())
                .name(dto.getName())
                .description(dto.getDescription())
                .price(dto.getPrice())
                .availableQuantity(dto.getAvailableQuantity())
                .category(dto.getCategory())
                .build();
    }

    public static ProductDTO toProductDTO(Product entity) {
        if (entity == null) return null;

        ProductDTO dto = new ProductDTO();
        dto.setId(entity.getId());
        dto.setName(entity.getName());
        dto.setDescription(entity.getDescription());
        dto.setPrice(entity.getPrice());
        dto.setAvailableQuantity(entity.getAvailableQuantity());
        dto.setCategory(entity.getCategory());
        return dto;
    }

    // Cart mapping
    public static Cart toCart(CartDTO dto) {
        if (dto == null) return null;

        return Cart.builder()
                .userId(dto.getUserId())
                .items(dto.getItems().stream()
                        .map(itemDto -> Cart.CartItem.builder()
                                .productId(itemDto.getProductId())
                                .quantity(itemDto.getQuantity())
                                .build())
                        .collect(Collectors.toList()))
                .build();
    }

    public static CartDTO toCartDTO(Cart entity) {
        if (entity == null) return null;

        CartDTO dto = new CartDTO();
        dto.setUserId(entity.getUserId());
        dto.setItems(entity.getItems().stream()
                .map(item -> {
                    CartDTO.CartItemDTO itemDto = new CartDTO.CartItemDTO();
                    itemDto.setProductId(item.getProductId());
                    itemDto.setQuantity(item.getQuantity());
                    return itemDto;
                })
                .collect(Collectors.toList()));
        return dto;
    }

    // Order mapping
    public static Order toOrder(OrderDTO dto) {
        if (dto == null) return null;

        return Order.builder()
                .id(dto.getId())
                .userId(dto.getUserId())
                .items(dto.getItems().stream()
                        .map(itemDto -> Order.OrderItem.builder()
                                .productId(itemDto.getProductId())
                                .quantity(itemDto.getQuantity())
                                .unitPrice(itemDto.getUnitPrice())
                                .build())
                        .collect(Collectors.toList()))
                .totalAmount(dto.getTotalAmount())
                .status(mapOrderStatus(dto.getStatus()))
                .build();
    }

    public static OrderDTO toOrderDTO(Order entity) {
        if (entity == null) return null;

        OrderDTO dto = new OrderDTO();
        dto.setId(entity.getId());
        dto.setUserId(entity.getUserId());
        dto.setItems(entity.getItems().stream()
                .map(item -> {
                    OrderDTO.OrderItemDTO itemDto = new OrderDTO.OrderItemDTO();
                    itemDto.setProductId(item.getProductId());
                    itemDto.setQuantity(item.getQuantity());
                    itemDto.setUnitPrice(item.getUnitPrice());
                    return itemDto;
                })
                .collect(Collectors.toList()));
        dto.setTotalAmount(entity.getTotalAmount());
        dto.setStatus(mapOrderStatusDto(entity.getStatus()));
        return dto;
    }

    // Helper methods for order status mapping
    private static Order.OrderStatus mapOrderStatus(com.ecommerce.validation.OrderStatus dtoStatus) {
        if (dtoStatus == null) return Order.OrderStatus.PENDING;

        return switch (dtoStatus) {
            case PENDING -> Order.OrderStatus.PENDING;
            case CONFIRMED, SHIPPED, DELIVERED -> Order.OrderStatus.COMPLETED;
            case CANCELED -> Order.OrderStatus.CANCELLED;
        };
    }

    private static com.ecommerce.validation.OrderStatus mapOrderStatusDto(Order.OrderStatus entityStatus) {
        if (entityStatus == null) return com.ecommerce.validation.OrderStatus.PENDING;

        return switch (entityStatus) {
            case PENDING -> com.ecommerce.validation.OrderStatus.PENDING;
            case COMPLETED -> com.ecommerce.validation.OrderStatus.DELIVERED;
            case CANCELLED -> com.ecommerce.validation.OrderStatus.CANCELED;
        };
    }
}