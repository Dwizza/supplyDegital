package org.example.digitallogisticssupplychainplatform.service;

import org.springframework.transaction.annotation.Transactional;
import org.example.digitallogisticssupplychainplatform.dto.*;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.mapper.*;
import org.example.digitallogisticssupplychainplatform.repository.*;
import org.example.digitallogisticssupplychainplatform.exception.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class SalesOrderLineService {

    private final SalesOrderLineRepository lineRepository;
    private final SalesOrderRepository orderRepository;
    private final ProductRepository productRepository;
    private final SalesOrderLineMapper lineMapper;

    @Transactional(readOnly = true)
    public List<SalesOrderLineDTO> findByOrderId(Long orderId) {
        return lineRepository.findBySalesOrderId(orderId).stream()
                .map(lineMapper::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public SalesOrderLineDTO findById(Long id) {
        SalesOrderLine line = lineRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Order line not found with id: " + id));
        return lineMapper.toDTO(line);
    }

    public SalesOrderLineDTO addLineToOrder(Long orderId, SalesOrderLineCreateDTO dto) {
        SalesOrder order = orderRepository.findById(orderId)
                .orElseThrow(() -> new ResourceNotFoundException("Sales order not found with id: " + orderId));

        Product product = productRepository.findById(dto.getProductId())
                .orElseThrow(() -> new ResourceNotFoundException("Product not found with id: " + dto.getProductId()));

        SalesOrderLine line = lineMapper.toEntity(dto);
        line.setProduct(product);
        order.addOrderLine(line);

        orderRepository.save(order);
        return lineMapper.toDTO(line);
    }

    public SalesOrderLineDTO updateLine(Long lineId, SalesOrderLineUpdateDTO dto) {
        SalesOrderLine line = lineRepository.findById(lineId)
                .orElseThrow(() -> new ResourceNotFoundException("Order line not found with id: " + lineId));

        lineMapper.updateEntityFromDTO(dto, line);
        SalesOrderLine updated = lineRepository.save(line);
        return lineMapper.toDTO(updated);
    }

    public void deleteLine(Long lineId) {
        SalesOrderLine line = lineRepository.findById(lineId)
                .orElseThrow(() -> new ResourceNotFoundException("Order line not found with id: " + lineId));

        SalesOrder order = line.getSalesOrder();
        order.removeOrderLine(line);
        orderRepository.save(order);
    }
}
