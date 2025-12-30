package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.PurchaseOrderLineDTO;
import org.example.digitallogisticssupplychainplatform.entity.PurchaseOrderLine;
import org.example.digitallogisticssupplychainplatform.mapper.PurchaseOrderMapper;
import org.example.digitallogisticssupplychainplatform.repository.PurchaseOrderLineRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PurchaseOrderLineService {

    private final PurchaseOrderLineRepository purchaseOrderLineRepository;
    private final PurchaseOrderMapper purchaseOrderMapper;

    @Transactional(readOnly = true)
    public List<PurchaseOrderLineDTO> getAllOrderLines() {
        return purchaseOrderLineRepository.findAll().stream()
                .map(purchaseOrderMapper::toLineDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public PurchaseOrderLineDTO getOrderLineById(Long id) {
        PurchaseOrderLine orderLine = purchaseOrderLineRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Purchase order line not found with id: " + id));
        return purchaseOrderMapper.toLineDTO(orderLine);
    }

    @Transactional(readOnly = true)
    public List<PurchaseOrderLineDTO> getOrderLinesByPurchaseOrder(Long purchaseOrderId) {
        return purchaseOrderLineRepository.findByPurchaseOrderId(purchaseOrderId).stream()
                .map(purchaseOrderMapper::toLineDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PurchaseOrderLineDTO> getOrderLinesByProduct(Long productId) {
        return purchaseOrderLineRepository.findByProductId(productId).stream()
                .map(purchaseOrderMapper::toLineDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PurchaseOrderLineDTO> getPendingOrderLinesByProduct(Long productId) {
        return purchaseOrderLineRepository.findPendingOrderLinesByProductId(productId).stream()
                .map(purchaseOrderMapper::toLineDTO)
                .collect(Collectors.toList());
    }

    @Transactional
    public void deleteOrderLine(Long id) {
        PurchaseOrderLine orderLine = purchaseOrderLineRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Purchase order line not found with id: " + id));
        purchaseOrderLineRepository.delete(orderLine);
    }

    @Transactional(readOnly = true)
    public Double getTotalQuantityOrderedByProduct(Long productId) {
        List<PurchaseOrderLine> orderLines = purchaseOrderLineRepository.findByProductId(productId);
        return orderLines.stream()
                .mapToDouble(PurchaseOrderLine::getQuantity)
                .sum();
    }
}