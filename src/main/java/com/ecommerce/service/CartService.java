package com.ecommerce.service;

import com.ecommerce.dto.CartDTO;
import com.ecommerce.exception.CustomBusinessException;

public interface CartService {
    CartDTO getCartByUserId(String userId) throws CustomBusinessException;

    CartDTO addItemToCart(String userId, CartDTO.CartItemDTO item) throws CustomBusinessException;

    CartDTO removeItemFromCart(String userId, String productId) throws CustomBusinessException;

    void clearCart(String userId) throws CustomBusinessException;
}
