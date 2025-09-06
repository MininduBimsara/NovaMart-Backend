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
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
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

            String username = extractUsernameFromAuth(authentication);
            log.info("Extracted username: {}", username);

            if (username == null || username.trim().isEmpty()) {
                log.error("Could not extract username from authentication");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            purchaseDTO.setUsername(username);

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
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            List<PurchaseDTO> purchases = purchaseService.getPurchasesByUsername(username);
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
            String username = extractUsernameFromAuth(authentication);
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            PurchaseDTO purchase = purchaseService.getPurchaseById(id);

            // Ensure user can only access their own purchases (unless admin)
            if (!purchase.getUsername().equals(username) && !isAdmin(authentication)) {
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

    // Response DTOs for options endpoints
    public record DeliveryLocationOption(String value, String label) {}
    public record DeliveryTimeOption(String value, String label) {}
    public record ProductOption(String value, String label) {}
}