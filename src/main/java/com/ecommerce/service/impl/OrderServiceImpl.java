package com.ecommerce.service.impl;

import com.ecommerce.domain.Order;
import com.ecommerce.dto.OrderDTO;
import com.ecommerce.exception.CustomBusinessException;
import com.ecommerce.repository.OrderRepository;
import com.ecommerce.service.OrderService;
import com.ecommerce.util.MapperUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class OrderServiceImpl implements OrderService {

    private final OrderRepository orderRepository;

    @Override
    public OrderDTO createOrder(OrderDTO orderDTO) throws CustomBusinessException {
        if (orderDTO.getItems() == null || orderDTO.getItems().isEmpty()) {
            throw new CustomBusinessException("Order must have at least one item");
        }

        Order order = MapperUtil.toOrder(orderDTO);
        order.setStatus(Order.OrderStatus.PENDING);
        order.setCreatedAt(Instant.now());

        Order savedOrder = orderRepository.save(order);
        return MapperUtil.toOrderDTO(savedOrder);
    }

    @Override
    public List<OrderDTO> getOrdersByUserId(String userId) {
        return orderRepository.findByUserId(userId).stream()
                .map(MapperUtil::toOrderDTO)
                .collect(Collectors.toList());
    }

    @Override
    public OrderDTO getOrderById(String id) throws CustomBusinessException {
        Order order = orderRepository.findById(id)
                .orElseThrow(() -> new CustomBusinessException("Order not found with id: " + id));
        return MapperUtil.toOrderDTO(order);
    }

    @Override
    public OrderDTO updateOrder(String id, OrderDTO orderDTO) throws CustomBusinessException {
        Order existingOrder = orderRepository.findById(id)
                .orElseThrow(() -> new CustomBusinessException("Order not found with id: " + id));

        existingOrder.setStatus(MapperUtil.toOrder(orderDTO).getStatus());
        existingOrder.setUpdatedAt(Instant.now());

        Order updatedOrder = orderRepository.save(existingOrder);
        return MapperUtil.toOrderDTO(updatedOrder);
    }

    @Override
    public void deleteOrder(String id) throws CustomBusinessException {
        Order order = orderRepository.findById(id)
                .orElseThrow(() -> new CustomBusinessException("Order not found with id: " + id));
        orderRepository.delete(order);
    }
}