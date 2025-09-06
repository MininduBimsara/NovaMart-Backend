// src/main/java/com/ecommerce/controller/OrderController.java - FIXED VERSION
package com.ecommerce.controller;

import com.ecommerce.dto.OrderDTO;
import com.ecommerce.service.OrderService;
import com.ecommerce.util.AuthenticationUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
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
            log.info("=== ORDER CREATION REQUEST ===");
            log.info("Authentication object: {}", authentication);
            log.info("OrderDTO received: {}", orderDTO);

            if (authentication == null) {
                log.error("Authentication is null!");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // Use unified username extraction
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            log.info("Extracted username: {}", username);

            if (username == null || username.trim().isEmpty()) {
                log.error("Username is null or empty!");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // Set the user ID for the order
            orderDTO.setUserId(username);
            log.info("OrderDTO with userId set: {}", orderDTO.getUserId());

            OrderDTO createdOrder = orderService.createOrder(orderDTO);
            log.info("Order created successfully with ID: {}", createdOrder.getId());

            return new ResponseEntity<>(createdOrder, HttpStatus.CREATED);

        } catch (Exception e) {
            log.error("Error creating order: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping
    @Operation(summary = "Get user orders", description = "Returns all orders for authenticated user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<OrderDTO>> getUserOrders(Authentication authentication) {
        try {
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            List<OrderDTO> orders = orderService.getOrdersByUserId(username);
            log.info("Retrieved {} orders for user: {}", orders.size(), username);
            return ResponseEntity.ok(orders);
        } catch (Exception e) {
            log.error("Error fetching user orders: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get order by ID", description = "Returns a specific order")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<OrderDTO> getOrderById(@PathVariable String id, Authentication authentication) {
        try {
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            OrderDTO order = orderService.getOrderById(id);

            // Ensure user can only access their own orders (unless admin)
            if (!order.getUserId().equals(username) && !AuthenticationUtil.isAdmin(authentication)) {
                log.warn("User {} attempted to access order {} belonging to {}",
                        username, id, order.getUserId());
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            return ResponseEntity.ok(order);
        } catch (Exception e) {
            log.error("Error fetching order: {}", e.getMessage(), e);
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
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            OrderDTO existingOrder = orderService.getOrderById(id);

            // Ensure user can only update their own orders (unless admin)
            if (!existingOrder.getUserId().equals(username) && !AuthenticationUtil.isAdmin(authentication)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            OrderDTO updatedOrder = orderService.updateOrder(id, orderDTO);
            return ResponseEntity.ok(updatedOrder);
        } catch (Exception e) {
            log.error("Error updating order: {}", e.getMessage(), e);
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
            log.error("Error deleting order: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}