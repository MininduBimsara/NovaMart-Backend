package com.ecommerce.controller;

import com.ecommerce.dto.OrderDTO;
import com.ecommerce.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
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
            log.info("=== ORDER CREATION DEBUG ===");
            log.info("Authentication object: {}", authentication);
            log.info("Authentication name: {}", authentication != null ? authentication.getName() : "null");
            log.info("Authentication authorities: {}", authentication != null ? authentication.getAuthorities() : "null");
            log.info("Security context: {}", SecurityContextHolder.getContext().getAuthentication());
            log.info("OrderDTO received: {}", orderDTO);

            if (authentication == null) {
                log.error("Authentication is null!");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // Extract username from authentication
            String username = extractUsernameFromAuth(authentication);
            log.info("Extracted username: {}", username);

            if (username == null || username.trim().isEmpty()) {
                log.error("Username is null or empty!");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // Set the user ID for the order
            orderDTO.setUserId(username);
            log.info("OrderDTO after setting userId: {}", orderDTO.getUserId());
            log.info("=== END DEBUG ===");

            OrderDTO createdOrder = orderService.createOrder(orderDTO);
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
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            List<OrderDTO> orders = orderService.getOrdersByUserId(username);
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

    /**
     * ASGARDEO-OPTIMIZED username extraction
     * Works with your current Asgardeo token configuration
     */
    private String extractUsernameFromAuth(Authentication authentication) {
        if (authentication == null) {
            log.error("Authentication is null");
            return null;
        }

        log.info("=== EXTRACTING USERNAME ===");
        log.info("Authentication type: {}", authentication.getClass().getSimpleName());
        log.info("Principal type: {}", authentication.getPrincipal().getClass().getSimpleName());

        // For Asgardeo JWT tokens
        if (authentication.getPrincipal() instanceof Jwt jwt) {

            log.info("Available JWT claims: {}", jwt.getClaims().keySet());
            log.debug("All JWT claims: {}", jwt.getClaims());

            // PRIORITY ORDER for your Asgardeo configuration:

            // 1. preferred_username (most reliable for Asgardeo)
            String username = jwt.getClaimAsString("preferred_username");
            if (username != null && !username.trim().isEmpty()) {
                log.info("Using preferred_username: {}", username);
                return username;
            }

            // 2. email (good backup for Asgardeo)
            username = jwt.getClaimAsString("email");
            if (username != null && !username.trim().isEmpty()) {
                log.info("Using email as username: {}", username);
                return username;
            }

            // 3. userid (Asgardeo specific user ID)
            username = jwt.getClaimAsString("userid");
            if (username != null && !username.trim().isEmpty()) {
                log.info("Using userid: {}", username);
                return username;
            }

            // 4. name (user's display name)
            username = jwt.getClaimAsString("name");
            if (username != null && !username.trim().isEmpty()) {
                log.info("Using name: {}", username);
                return username;
            }

            // 5. given_name (first name as fallback)
            username = jwt.getClaimAsString("given_name");
            if (username != null && !username.trim().isEmpty()) {
                log.info("Using given_name: {}", username);
                return username;
            }

            // 6. username claim (generic username)
            username = jwt.getClaimAsString("username");
            if (username != null && !username.trim().isEmpty()) {
                log.info("Using username claim: {}", username);
                return username;
            }

            // 7. Final fallback to subject
            username = jwt.getSubject();
            log.info("Using subject as final fallback: {}", username);
            return username;
        }

        // For local JWT tokens (string principal)
        String name = authentication.getName();
        if (name != null && !name.trim().isEmpty() && !name.equals("anonymousUser")) {
            log.info("Using authentication name (local JWT): {}", name);
            return name;
        }

        // Try to get principal if it's a string
        Object principal = authentication.getPrincipal();
        if (principal instanceof String stringPrincipal && !stringPrincipal.trim().isEmpty()) {
            log.info("Using string principal: {}", stringPrincipal);
            return stringPrincipal;
        }

        // If principal is UserDetails, extract username
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails userDetails) {
            log.info("Using UserDetails username: {}", userDetails.getUsername());
            return userDetails.getUsername();
        }

        log.error("Could not extract username from authentication: {}", authentication);
        return null;
    }

    private boolean isAdmin(Authentication authentication) {
        if (authentication == null) {
            return false;
        }

        boolean hasAdminAuthority = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority -> {
                    String auth = authority.toUpperCase();
                    return auth.equals("ROLE_ADMIN") ||
                            auth.equals("ADMIN") ||
                            auth.contains("ADMIN") ||
                            auth.equals("ROLE_ADMINISTRATOR") ||
                            auth.equals("ADMINISTRATOR");
                });

        log.info("Admin check for user - Has admin authority: {}", hasAdminAuthority);
        log.debug("User authorities: {}", authentication.getAuthorities());

        return hasAdminAuthority;
    }
}