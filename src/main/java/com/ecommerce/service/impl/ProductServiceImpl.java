package com.ecommerce.service.impl;

import com.ecommerce.domain.Product;
import com.ecommerce.dto.ProductDTO;
import com.ecommerce.exception.CustomBusinessException;
import com.ecommerce.repository.ProductRepository;
import com.ecommerce.service.ProductService;
import com.ecommerce.util.MapperUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ProductServiceImpl implements ProductService {

    private final ProductRepository productRepository;

    @Override
    public ProductDTO createProduct(ProductDTO productDTO) throws CustomBusinessException {
        if (productDTO.getAvailableQuantity() < 0) {
            throw new CustomBusinessException("Available quantity cannot be negative");
        }
        Product product = MapperUtil.toProduct(productDTO);
        Product saved = productRepository.save(product);
        return MapperUtil.toProductDTO(saved);
    }

    @Override
    public List<ProductDTO> getAllProducts() {
        return productRepository.findAll().stream()
                .map(MapperUtil::toProductDTO)
                .collect(Collectors.toList());
    }

    @Override
    public ProductDTO getProductById(String id) throws CustomBusinessException {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new CustomBusinessException("Product not found with id: " + id));
        return MapperUtil.toProductDTO(product);
    }

    @Override
    public ProductDTO updateProduct(String id, ProductDTO productDTO) throws CustomBusinessException {
        Product existing = productRepository.findById(id)
                .orElseThrow(() -> new CustomBusinessException("Product not found with id: " + id));
        if (productDTO.getAvailableQuantity() < 0) {
            throw new CustomBusinessException("Available quantity cannot be negative");
        }
        existing.setName(productDTO.getName());
        existing.setDescription(productDTO.getDescription());
        existing.setPrice(productDTO.getPrice());
        existing.setAvailableQuantity(productDTO.getAvailableQuantity());
        existing.setCategory(productDTO.getCategory());
        Product updated = productRepository.save(existing);
        return MapperUtil.toProductDTO(updated);
    }

    @Override
    public void deleteProduct(String id) throws CustomBusinessException {
        Product existing = productRepository.findById(id)
                .orElseThrow(() -> new CustomBusinessException("Product not found with id: " + id));
        productRepository.delete(existing);
    }
}
