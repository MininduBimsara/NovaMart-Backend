// src/main/java/com/ecommerce/controller/PurchaseController.java - FIXED VERSION
package com.ecommerce.controller;

import com.ecommerce.dto.PurchaseDTO;
import com.ecommerce.service.PurchaseService;
import com.ecommerce.util.AuthenticationUtil;
import com.ecommerce.validation.DeliveryLocation;
import com.ecommerce.validation.DeliveryTime;
import com.ecommerce.validation.ProductName;
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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/purchases")
@RequiredArgsConstructor
@Tag(name = "Purchase Management", description = "Purchase creation and management with Sri Lankan delivery options")
public class PurchaseController {

    private final PurchaseService purchaseService;

    @PostMapping
    @Operation(summary = "Create purchase", description = "Creates a new purchase order with delivery details")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<PurchaseDTO> createPurchase(@Valid @RequestBody PurchaseDTO purchaseDTO,
                                                      Authentication authentication) {
        try {
            log.info("=== PURCHASE CREATION DEBUG ===");
            log.info("Authentication: {}", authentication);
            log.info("PurchaseDTO received: {}", purchaseDTO);

            // Extract username using the unified utility
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            log.info("Extracted username: {}", username);

            if (username == null || username.trim().isEmpty()) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // CRITICAL FIX: Always override the username from the JWT token
            // Don't rely on frontend to send the correct username
            purchaseDTO.setUsername(username);
            log.info("Set username in purchaseDTO: {}", purchaseDTO.getUsername());

            // Validate that all required fields are present
            if (purchaseDTO.getPurchaseDate() == null) {
                log.error("Purchase date is null");
                return ResponseEntity.badRequest().build();
            }

            if (purchaseDTO.getDeliveryTime() == null || purchaseDTO.getDeliveryTime().trim().isEmpty()) {
                log.error("Delivery time is null or empty");
                return ResponseEntity.badRequest().build();
            }

            if (purchaseDTO.getDeliveryLocation() == null || purchaseDTO.getDeliveryLocation().trim().isEmpty()) {
                log.error("Delivery location is null or empty");
                return ResponseEntity.badRequest().build();
            }

            if (purchaseDTO.getProductName() == null || purchaseDTO.getProductName().trim().isEmpty()) {
                log.error("Product name is null or empty");
                return ResponseEntity.badRequest().build();
            }

            if (purchaseDTO.getQuantity() == null || purchaseDTO.getQuantity() < 1) {
                log.error("Quantity is invalid: {}", purchaseDTO.getQuantity());
                return ResponseEntity.badRequest().build();
            }

            log.info("All validation checks passed, creating purchase...");

            PurchaseDTO createdPurchase = purchaseService.createPurchase(purchaseDTO);
            log.info("Purchase created successfully: {}", createdPurchase.getId());

            return new ResponseEntity<>(createdPurchase, HttpStatus.CREATED);
        } catch (Exception e) {
            log.error("Error creating purchase: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping
    @Operation(summary = "Get user purchases", description = "Returns all purchases for authenticated user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<PurchaseDTO>> getUserPurchases(Authentication authentication) {
        try {
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            List<PurchaseDTO> purchases = purchaseService.getPurchasesByUsername(username);
            log.info("Retrieved {} purchases for user: {}", purchases.size(), username);
            return ResponseEntity.ok(purchases);
        } catch (Exception e) {
            log.error("Error fetching user purchases: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get purchase by ID", description = "Returns a specific purchase")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<PurchaseDTO> getPurchaseById(@PathVariable String id, Authentication authentication) {
        try {
            String username = AuthenticationUtil.extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            PurchaseDTO purchase = purchaseService.getPurchaseById(id);

            // Ensure user can only access their own purchases (unless admin)
            if (!purchase.getUsername().equals(username) && !AuthenticationUtil.isAdmin(authentication)) {
                log.warn("User {} attempted to access purchase {} belonging to {}",
                        username, id, purchase.getUsername());
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            return ResponseEntity.ok(purchase);
        } catch (Exception e) {
            log.error("Error fetching purchase: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("/admin/all")
    @Operation(summary = "Get all purchases (Admin)", description = "Returns all purchases in the system (Admin only)")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PurchaseDTO>> getAllPurchases() {
        try {
            List<PurchaseDTO> purchases = purchaseService.getAllPurchases();
            return ResponseEntity.ok(purchases);
        } catch (Exception e) {
            log.error("Error fetching all purchases: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // Options endpoints for frontend dropdowns
    @GetMapping("/options/delivery-locations")
    @Operation(summary = "Get delivery locations", description = "Returns all available Sri Lankan delivery locations")
    public ResponseEntity<List<DeliveryLocationOption>> getDeliveryLocations() {
        List<DeliveryLocationOption> locations = Arrays.stream(DeliveryLocation.values())
                .map(location -> new DeliveryLocationOption(location.name(), location.getDisplayName()))
                .collect(Collectors.toList());
        return ResponseEntity.ok(locations);
    }

    @GetMapping("/options/delivery-times")
    @Operation(summary = "Get delivery times", description = "Returns all available delivery time slots")
    public ResponseEntity<List<DeliveryTimeOption>> getDeliveryTimes() {
        List<DeliveryTimeOption> times = Arrays.stream(DeliveryTime.values())
                .map(time -> new DeliveryTimeOption(time.name(), time.getDisplayTime()))
                .collect(Collectors.toList());
        return ResponseEntity.ok(times);
    }

    @GetMapping("/options/products")
    @Operation(summary = "Get available products", description = "Returns all available products for purchase")
    public ResponseEntity<List<ProductOption>> getAvailableProducts() {
        List<ProductOption> products = Arrays.stream(ProductName.values())
                .map(product -> new ProductOption(product.name(), product.getDisplayName()))
                .collect(Collectors.toList());
        return ResponseEntity.ok(products);
    }

    // Response DTOs for options endpoints
    public record DeliveryLocationOption(String value, String label) {}
    public record DeliveryTimeOption(String value, String label) {}
    public record ProductOption(String value, String label) {}
}