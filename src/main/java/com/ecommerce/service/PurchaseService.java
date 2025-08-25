package com.ecommerce.service;

import com.ecommerce.dto.PurchaseDTO;
import com.ecommerce.exception.CustomBusinessException;

import java.util.List;

public interface PurchaseService {
    PurchaseDTO createPurchase(PurchaseDTO purchaseDTO) throws CustomBusinessException;
    List<PurchaseDTO> getPurchasesByUsername(String username);
    PurchaseDTO getPurchaseById(String id) throws CustomBusinessException;
    List<PurchaseDTO> getAllPurchases(); // Admin only
}