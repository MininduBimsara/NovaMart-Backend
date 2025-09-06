// src/main/java/com/ecommerce/controller/CartController.java - FIXED VERSION
package com.ecommerce.controller;

import com.ecommerce.dto.CartDTO;
import com.ecommerce.service.CartService;
import com.ecommerce.util.AuthenticationUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            if (username == null) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(401).build();
            }

            log.info("Getting cart for user: {}", username);
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
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            if (username == null) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(401).build();
            }

            log.info("Adding item to cart for user: {} - Product: {}, Quantity: {}",
                    username, item.getProductId(), item.getQuantity());

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
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            if (username == null) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(401).build();
            }

            log.info("Removing item from cart for user: {} - Product: {}", username, productId);
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
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            if (username == null) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(401).build();
            }

            log.info("Clearing cart for user: {}", username);
            cartService.clearCart(username);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            log.error("Error clearing cart: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
}