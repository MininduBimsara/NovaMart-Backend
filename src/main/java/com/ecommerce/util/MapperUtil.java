package com.ecommerce.util;

import com.ecommerce.dto.UserDTO;
import com.ecommerce.dto.ProductDTO;
import com.ecommerce.domain.User;
import com.ecommerce.domain.Product;

public class MapperUtil {

    public static User toUser(UserDTO dto) {
        if (dto == null) return null;
        User u = new User();
        u.setUsername(dto.getUsername());
        u.setEmail(dto.getEmail());
        u.setPassword(dto.getPassword());
        u.setRoles(dto.getRoles());
        return u;
    }

    public static UserDTO toUserDTO(User entity) {
        if (entity == null) return null;
        UserDTO dto = new UserDTO();
        dto.setUsername(entity.getUsername());
        dto.setEmail(entity.getEmail());
        dto.setPassword(entity.getPassword());
        dto.setRoles(entity.getRoles());
        return dto;
    }

    public static Product toProduct(ProductDTO dto) {
        if (dto == null) return null;
        Product p = new Product();
        p.setName(dto.getName());
        p.setDescription(dto.getDescription());
        p.setPrice(dto.getPrice());
        p.setAvailableQuantity(dto.getAvailableQuantity());
        p.setCategory(dto.getCategory());
        return p;
    }

    public static ProductDTO toProductDTO(Product entity) {
        if (entity == null) return null;
        ProductDTO dto = new ProductDTO();
        dto.setName(entity.getName());
        dto.setDescription(entity.getDescription());
        dto.setPrice(entity.getPrice());
        dto.setAvailableQuantity(entity.getAvailableQuantity());
        dto.setCategory(entity.getCategory());
        return dto;
    }
}
