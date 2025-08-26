package com.ecommerce.service.impl;

import com.ecommerce.domain.Purchase;
import com.ecommerce.dto.PurchaseDTO;
import com.ecommerce.exception.CustomBusinessException;
import com.ecommerce.repository.PurchaseRepository;
import com.ecommerce.service.PurchaseService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PurchaseServiceImpl implements PurchaseService {

    private final PurchaseRepository purchaseRepository;

    @Override
    public PurchaseDTO createPurchase(PurchaseDTO purchaseDTO) throws CustomBusinessException {
        validatePurchaseDate(purchaseDTO.getPurchaseDate());

        Purchase purchase = Purchase.builder()
                .username(purchaseDTO.getUsername())
                .purchaseDate(purchaseDTO.getPurchaseDate())
                .deliveryTime(purchaseDTO.getDeliveryTime())
                .deliveryLocation(purchaseDTO.getDeliveryLocation())
                .productName(purchaseDTO.getProductName())
                .quantity(purchaseDTO.getQuantity())
                .message(purchaseDTO.getMessage())
                .status("PENDING")
                .build();

        Purchase savedPurchase = purchaseRepository.save(purchase);
        return mapToDTO(savedPurchase);
    }

    @Override
    public List<PurchaseDTO> getPurchasesByUsername(String username) {
        return purchaseRepository.findByUsernameOrderByPurchaseDateDesc(username)
                .stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Override
    public PurchaseDTO getPurchaseById(String id) throws CustomBusinessException {
        Purchase purchase = purchaseRepository.findById(id)
                .orElseThrow(() -> new CustomBusinessException("Purchase not found with id: " + id));
        return mapToDTO(purchase);
    }

    @Override
    public List<PurchaseDTO> getAllPurchases() {
        return purchaseRepository.findAllByOrderByPurchaseDateDesc()
                .stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    private void validatePurchaseDate(LocalDate date) throws CustomBusinessException {
        if (date == null) {
            throw new CustomBusinessException("Purchase date is required");
        }

        if (date.isBefore(LocalDate.now())) {
            throw new CustomBusinessException("Purchase date cannot be in the past");
        }

        if (date.getDayOfWeek() == DayOfWeek.SUNDAY) {
            throw new CustomBusinessException("Delivery is not available on Sundays");
        }
    }

    private PurchaseDTO mapToDTO(Purchase purchase) {
        return PurchaseDTO.builder()
                .id(purchase.getId())
                .username(purchase.getUsername())
                .purchaseDate(purchase.getPurchaseDate())
                .deliveryTime(purchase.getDeliveryTime())
                .deliveryLocation(purchase.getDeliveryLocation())
                .productName(purchase.getProductName())
                .quantity(purchase.getQuantity())
                .message(purchase.getMessage())
                .status(purchase.getStatus())
                .build();
    }
}