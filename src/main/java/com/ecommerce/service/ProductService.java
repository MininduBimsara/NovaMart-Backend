package com.ecommerce.service;

import com.ecommerce.dto.ProductDTO;
import com.ecommerce.exception.CustomBusinessException;

import java.util.List;

public interface ProductService {
    ProductDTO createProduct(ProductDTO productDTO) throws CustomBusinessException;

    List<ProductDTO> getAllProducts();

    ProductDTO getProductById(String id) throws CustomBusinessException;

    ProductDTO updateProduct(String id, ProductDTO productDTO) throws CustomBusinessException;

    void deleteProduct(String id) throws CustomBusinessException;
}
