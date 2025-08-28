package com.ecommerce.controller;

import com.ecommerce.dto.PurchaseDTO;
import com.ecommerce.service.PurchaseService;
import com.ecommerce.validation.DeliveryLocation;
import com.ecommerce.validation.DeliveryTime;
import com.ecommerce.validation.ProductName;
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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

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
                                                      @AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        purchaseDTO.setUsername(username);

        PurchaseDTO createdPurchase = purchaseService.createPurchase(purchaseDTO);
        return new ResponseEntity<>(createdPurchase, HttpStatus.CREATED);
    }

    @GetMapping
    @Operation(summary = "Get user purchases", description = "Returns all purchases for authenticated user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<PurchaseDTO>> getUserPurchases(@AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        List<PurchaseDTO> purchases = purchaseService.getPurchasesByUsername(username);
        return ResponseEntity.ok(purchases);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get purchase by ID", description = "Returns a specific purchase")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<PurchaseDTO> getPurchaseById(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        String username = extractUsername(jwt);
        PurchaseDTO purchase = purchaseService.getPurchaseById(id);

        // Ensure user can only access their own purchases (unless admin)
        if (!purchase.getUsername().equals(username) && !isAdmin(jwt)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        return ResponseEntity.ok(purchase);
    }

    @GetMapping("/admin/all")
    @Operation(summary = "Get all purchases (Admin)", description = "Returns all purchases in the system (Admin only)")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PurchaseDTO>> getAllPurchases() {
        List<PurchaseDTO> purchases = purchaseService.getAllPurchases();
        return ResponseEntity.ok(purchases);
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

    private String extractUsername(Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        if (username == null) {
            username = jwt.getClaimAsString("username");
        }
        if (username == null) {
            username = jwt.getClaimAsString("email");
        }
        if (username == null) {
            username = jwt.getSubject();
        }
        return username;
    }

    private boolean isAdmin(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("groups");
        if (roles == null) {
            roles = jwt.getClaimAsStringList("roles");
        }
        if (roles == null) {
            Object rolesObj = jwt.getClaim("authorities");
            if (rolesObj instanceof List<?>) {
                roles = ((List<?>) rolesObj).stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
            }
        }
        return roles != null && (roles.contains("ADMIN") || roles.contains("admin"));
    }

    // Response DTOs for options endpoints
    public record DeliveryLocationOption(String value, String label) {}
    public record DeliveryTimeOption(String value, String label) {}
    public record ProductOption(String value, String label) {}
}