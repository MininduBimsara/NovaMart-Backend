package com.ecommerce.controller;

import com.ecommerce.dto.CartDTO;
import com.ecommerce.service.CartService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/cart")
@RequiredArgsConstructor
@Tag(name = "Shopping Cart", description = "Shopping cart management")
public class CartController {

    private final CartService cartService;

    @GetMapping
    @Operation(summary = "Get user cart", description = "Returns the current user's shopping cart")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<CartDTO> getCart(@AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        CartDTO cart = cartService.getCartByUserId(username);
        return ResponseEntity.ok(cart);
    }

    @PostMapping("/items")
    @Operation(summary = "Add item to cart", description = "Adds a product item to the user's cart")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<CartDTO> addItemToCart(@Valid @RequestBody CartDTO.CartItemDTO item,
                                                 @AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        CartDTO updatedCart = cartService.addItemToCart(username, item);
        return ResponseEntity.ok(updatedCart);
    }

    @DeleteMapping("/items/{productId}")
    @Operation(summary = "Remove item from cart", description = "Removes a specific item from the cart")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<CartDTO> removeItemFromCart(@PathVariable String productId,
                                                      @AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        CartDTO updatedCart = cartService.removeItemFromCart(username, productId);
        return ResponseEntity.ok(updatedCart);
    }

    @DeleteMapping("/clear")
    @Operation(summary = "Clear cart", description = "Removes all items from the user's cart")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Void> clearCart(@AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        cartService.clearCart(username);
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
}