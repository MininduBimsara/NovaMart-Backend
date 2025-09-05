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
        System.out.println("=== ORDER CREATION DEBUG ===");
        System.out.println("Authentication object: " + authentication);
        System.out.println("Authentication name: " + (authentication != null ? authentication.getName() : "null"));
        System.out.println("Authentication authorities: " + (authentication != null ? authentication.getAuthorities() : "null"));
        System.out.println("OrderDTO before setting userId: " + orderDTO.getUserId());

        if (authentication == null) {
            System.out.println("Authentication is null!");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String username = authentication.getName();
        System.out.println("Username extracted: " + username);

        orderDTO.setUserId(username);
        System.out.println("OrderDTO after setting userId: " + orderDTO.getUserId());
        System.out.println("=== END DEBUG ===");

        OrderDTO createdOrder = orderService.createOrder(orderDTO);
        return new ResponseEntity<>(createdOrder, HttpStatus.CREATED);
    }

    @GetMapping
    @Operation(summary = "Get user orders", description = "Returns all orders for authenticated user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<OrderDTO>> getUserOrders(Authentication authentication) {
        String username = authentication.getName();
        List<OrderDTO> orders = orderService.getOrdersByUserId(username);
        return ResponseEntity.ok(orders);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get order by ID", description = "Returns a specific order")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<OrderDTO> getOrderById(@PathVariable String id, Authentication authentication) {
        String username = authentication.getName();
        OrderDTO order = orderService.getOrderById(id);

        // Ensure user can only access their own orders (unless admin)
        if (!order.getUserId().equals(username) && !isAdmin(authentication)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        return ResponseEntity.ok(order);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update order", description = "Updates an existing order")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<OrderDTO> updateOrder(@PathVariable String id,
                                                @Valid @RequestBody OrderDTO orderDTO,
                                                Authentication authentication) {
        String username = authentication.getName();
        OrderDTO existingOrder = orderService.getOrderById(id);

        // Ensure user can only update their own orders (unless admin)
        if (!existingOrder.getUserId().equals(username) && !isAdmin(authentication)) {
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

    private boolean isAdmin(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority -> authority.equals("ROLE_ADMIN"));
    }
}