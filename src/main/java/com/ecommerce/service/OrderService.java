package com.ecommerce.service;

import com.ecommerce.dto.OrderDTO;
import com.ecommerce.exception.CustomBusinessException;

import java.util.List;

public interface OrderService {
    OrderDTO createOrder(OrderDTO orderDTO) throws CustomBusinessException;
    List<OrderDTO> getOrdersByUserId(String userId);
    OrderDTO getOrderById(String id) throws CustomBusinessException;
    OrderDTO updateOrder(String id, OrderDTO orderDTO) throws CustomBusinessException;
    void deleteOrder(String id) throws CustomBusinessException;
}