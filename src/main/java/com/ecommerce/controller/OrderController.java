// src/main/java/com/ecommerce/controller/OrderController.java - FIXED VERSION
package com.ecommerce.controller;

import com.ecommerce.dto.OrderDTO;
import com.ecommerce.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/orders")
@RequiredArgsConstructor
@Tag(name = "Order Management", description = "Order creation and management")
public class OrderController {

    private final OrderService orderService;

    @PostMapping
    @Operation(summary = "Create order", description = "Creates a new order from cart or direct purchase")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<OrderDTO> createOrder(@Valid @RequestBody OrderDTO orderDTO,
                                                Authentication authentication) {
        try {
            System.out.println("=== ORDER CREATION DEBUG ===");
            System.out.println("Authentication object: " + authentication);
            System.out.println("Authentication name: " + (authentication != null ? authentication.getName() : "null"));
            System.out.println("Authentication authorities: " + (authentication != null ? authentication.getAuthorities() : "null"));
            System.out.println("Security context: " + SecurityContextHolder.getContext().getAuthentication());
            System.out.println("OrderDTO received: " + orderDTO);

            if (authentication == null) {
                System.out.println("Authentication is null!");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // Extract username from authentication
            String username = extractUsernameFromAuth(authentication);
            System.out.println("Extracted username: " + username);

            if (username == null || username.trim().isEmpty()) {
                System.out.println("Username is null or empty!");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // Set the user ID for the order
            orderDTO.setUserId(username);
            System.out.println("OrderDTO after setting userId: " + orderDTO.getUserId());
            System.out.println("=== END DEBUG ===");

            OrderDTO createdOrder = orderService.createOrder(orderDTO);
            return new ResponseEntity<>(createdOrder, HttpStatus.CREATED);

        } catch (Exception e) {
            System.err.println("Error creating order: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping
    @Operation(summary = "Get user orders", description = "Returns all orders for authenticated user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<OrderDTO>> getUserOrders(Authentication authentication) {
        try {
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            List<OrderDTO> orders = orderService.getOrdersByUserId(username);
            return ResponseEntity.ok(orders);
        } catch (Exception e) {
            System.err.println("Error fetching user orders: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get order by ID", description = "Returns a specific order")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<OrderDTO> getOrderById(@PathVariable String id, Authentication authentication) {
        try {
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            OrderDTO order = orderService.getOrderById(id);

            // Ensure user can only access their own orders (unless admin)
            if (!order.getUserId().equals(username) && !isAdmin(authentication)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            return ResponseEntity.ok(order);
        } catch (Exception e) {
            System.err.println("Error fetching order: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update order", description = "Updates an existing order")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<OrderDTO> updateOrder(@PathVariable String id,
                                                @Valid @RequestBody OrderDTO orderDTO,
                                                Authentication authentication) {
        try {
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            OrderDTO existingOrder = orderService.getOrderById(id);

            // Ensure user can only update their own orders (unless admin)
            if (!existingOrder.getUserId().equals(username) && !isAdmin(authentication)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            OrderDTO updatedOrder = orderService.updateOrder(id, orderDTO);
            return ResponseEntity.ok(updatedOrder);
        } catch (Exception e) {
            System.err.println("Error updating order: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete order", description = "Deletes an order")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteOrder(@PathVariable String id) {
        try {
            orderService.deleteOrder(id);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            System.err.println("Error deleting order: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Enhanced method to extract username from authentication
     */
    private String extractUsernameFromAuth(Authentication authentication) {
        if (authentication == null) {
            return null;
        }

        // Try to get the name (this should be the username)
        String name = authentication.getName();
        if (name != null && !name.trim().isEmpty() && !name.equals("anonymousUser")) {
            return name;
        }

        // Try to get principal if it's a string
        Object principal = authentication.getPrincipal();
        if (principal instanceof String && !((String) principal).trim().isEmpty()) {
            return (String) principal;
        }

        // If principal is UserDetails, extract username
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
            return ((org.springframework.security.core.userdetails.UserDetails) principal).getUsername();
        }

        System.err.println("Could not extract username from authentication: " + authentication);
        return null;
    }

    private boolean isAdmin(Authentication authentication) {
        if (authentication == null) {
            return false;
        }

        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority ->
                        authority.equals("ROLE_ADMIN") ||
                                authority.equals("ADMIN") ||
                                authority.toUpperCase().contains("ADMIN"));
    }
}