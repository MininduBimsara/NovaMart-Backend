package com.ecommerce.service.impl;

import com.ecommerce.domain.Cart;
import com.ecommerce.domain.Product;
import com.ecommerce.dto.CartDTO;
import com.ecommerce.exception.CustomBusinessException;
import com.ecommerce.repository.CartRepository;
import com.ecommerce.repository.ProductRepository;
import com.ecommerce.service.CartService;
import com.ecommerce.util.MapperUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CartServiceImpl implements CartService {

    private final CartRepository cartRepository;
    private final ProductRepository productRepository;

    @Override
    public CartDTO getCartByUserId(String userId) throws CustomBusinessException {
        Optional<Cart> cartOpt = cartRepository.findByUserId(userId);
        if (cartOpt.isEmpty()) {
            // Create empty cart if none exists
            Cart newCart = Cart.builder()
                    .userId(userId)
                    .build();
            Cart savedCart = cartRepository.save(newCart);
            return MapperUtil.toCartDTO(savedCart);
        }
        return MapperUtil.toCartDTO(cartOpt.get());
    }

    @Override
    public CartDTO addItemToCart(String userId, CartDTO.CartItemDTO item) throws CustomBusinessException {
        // Validate product exists
        Product product = productRepository.findById(item.getProductId())
                .orElseThrow(() -> new CustomBusinessException("Product not found with id: " + item.getProductId()));

        if (product.getAvailableQuantity() < item.getQuantity()) {
            throw new CustomBusinessException("Not enough stock available");
        }

        Cart cart = cartRepository.findByUserId(userId)
                .orElse(Cart.builder().userId(userId).build());

        // Check if item already exists in cart
        Optional<Cart.CartItem> existingItem = cart.getItems().stream()
                .filter(cartItem -> cartItem.getProductId().equals(item.getProductId()))
                .findFirst();

        if (existingItem.isPresent()) {
            existingItem.get().setQuantity(existingItem.get().getQuantity() + item.getQuantity());
        } else {
            Cart.CartItem newItem = Cart.CartItem.builder()
                    .productId(item.getProductId())
                    .quantity(item.getQuantity())
                    .unitPrice(product.getPrice())
                    .build();
            cart.getItems().add(newItem);
        }

        cart.setUpdatedAt(Instant.now());
        Cart savedCart = cartRepository.save(cart);
        return MapperUtil.toCartDTO(savedCart);
    }

    @Override
    public CartDTO removeItemFromCart(String userId, String productId) throws CustomBusinessException {
        Cart cart = cartRepository.findByUserId(userId)
                .orElseThrow(() -> new CustomBusinessException("Cart not found for user: " + userId));

        cart.getItems().removeIf(item -> item.getProductId().equals(productId));
        cart.setUpdatedAt(Instant.now());

        Cart savedCart = cartRepository.save(cart);
        return MapperUtil.toCartDTO(savedCart);
    }

    @Override
    public void clearCart(String userId) throws CustomBusinessException {
        Cart cart = cartRepository.findByUserId(userId)
                .orElseThrow(() -> new CustomBusinessException("Cart not found for user: " + userId));

        cart.getItems().clear();
        cart.setUpdatedAt(Instant.now());
        cartRepository.save(cart);
    }
}