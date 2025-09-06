package com.ecommerce.controller;

import com.ecommerce.dto.CartDTO;
import com.ecommerce.service.CartService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/cart")
@RequiredArgsConstructor
@Tag(name = "Shopping Cart", description = "Shopping cart management")
public class CartController {

    private final CartService cartService;

    @GetMapping
    @Operation(summary = "Get user cart", description = "Returns the current user's shopping cart")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<CartDTO> getCart(Authentication authentication) {
        try {
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(401).build();
            }

            CartDTO cart = cartService.getCartByUserId(username);
            return ResponseEntity.ok(cart);
        } catch (Exception e) {
            log.error("Error fetching cart: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }

    @PostMapping("/items")
    @Operation(summary = "Add item to cart", description = "Adds a product item to the user's cart")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<CartDTO> addItemToCart(@Valid @RequestBody CartDTO.CartItemDTO item,
                                                 Authentication authentication) {
        try {
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(401).build();
            }

            CartDTO updatedCart = cartService.addItemToCart(username, item);
            return ResponseEntity.ok(updatedCart);
        } catch (Exception e) {
            log.error("Error adding item to cart: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }

    @DeleteMapping("/items/{productId}")
    @Operation(summary = "Remove item from cart", description = "Removes a specific item from the cart")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<CartDTO> removeItemFromCart(@PathVariable String productId,
                                                      Authentication authentication) {
        try {
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(401).build();
            }

            CartDTO updatedCart = cartService.removeItemFromCart(username, productId);
            return ResponseEntity.ok(updatedCart);
        } catch (Exception e) {
            log.error("Error removing item from cart: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }

    @DeleteMapping("/clear")
    @Operation(summary = "Clear cart", description = "Removes all items from the user's cart")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Void> clearCart(Authentication authentication) {
        try {
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(401).build();
            }

            cartService.clearCart(username);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            log.error("Error clearing cart: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
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

    // Enhanced admin check method
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