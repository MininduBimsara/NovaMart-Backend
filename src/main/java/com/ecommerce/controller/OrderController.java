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
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

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
                                                @AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        orderDTO.setUserId(username);

        OrderDTO createdOrder = orderService.createOrder(orderDTO);
        return new ResponseEntity<>(createdOrder, HttpStatus.CREATED);
    }

    @GetMapping
    @Operation(summary = "Get user orders", description = "Returns all orders for authenticated user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<OrderDTO>> getUserOrders(@AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        List<OrderDTO> orders = orderService.getOrdersByUserId(username);
        return ResponseEntity.ok(orders);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get order by ID", description = "Returns a specific order")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<OrderDTO> getOrderById(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        OrderDTO order = orderService.getOrderById(id);

        // Ensure user can only access their own orders (unless admin)
        if (!order.getUserId().equals(username) && !isAdmin(jwt)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        return ResponseEntity.ok(order);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update order", description = "Updates an existing order")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<OrderDTO> updateOrder(@PathVariable String id,
                                                @Valid @RequestBody OrderDTO orderDTO,
                                                @AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        OrderDTO existingOrder = orderService.getOrderById(id);

        // Ensure user can only update their own orders (unless admin)
        if (!existingOrder.getUserId().equals(username) && !isAdmin(jwt)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        OrderDTO updatedOrder = orderService.updateOrder(id, orderDTO);
        return ResponseEntity.ok(updatedOrder);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete order", description = "Deletes an order")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteOrder(@PathVariable String id) {
        orderService.deleteOrder(id);
        return ResponseEntity.noContent().build();
    }

    private String extractUsername(Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        if (username == null) {
            username = jwt.getClaimAsString("username");
        }
        if (username == null) {
            username = jwt.getSubject();
        }
        return username;
    }

    private boolean isAdmin(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles == null) {
            Object rolesObj = jwt.getClaim("authorities");
            if (rolesObj instanceof List<?>) {
                roles = ((List<?>) rolesObj).stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
            }
        }
        return roles != null && roles.contains("ADMIN");
    }
}