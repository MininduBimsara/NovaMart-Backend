package com.ecommerce.repository;

import com.ecommerce.domain.Purchase;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PurchaseRepository extends MongoRepository<Purchase, String> {
    List<Purchase> findByUsernameOrderByPurchaseDateDesc(String username);
    List<Purchase> findAllByOrderByPurchaseDateDesc();
}