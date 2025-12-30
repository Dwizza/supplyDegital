package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.*;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.mapper.PurchaseOrderMapper;
import org.example.digitallogisticssupplychainplatform.repository.PurchaseOrderRepository;
import org.example.digitallogisticssupplychainplatform.repository.SupplierRepository;
import org.example.digitallogisticssupplychainplatform.repository.UserRepository;
import org.example.digitallogisticssupplychainplatform.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PurchaseOrderService {

    private final PurchaseOrderRepository purchaseOrderRepository;
    private final SupplierRepository supplierRepository;
    private final UserRepository userRepository;
    private final ProductRepository productRepository;
    private final PurchaseOrderMapper purchaseOrderMapper;

    @Transactional
    public PurchaseOrderDTO createPurchaseOrder(CreatePurchaseOrderRequest request) {
        Supplier supplier = supplierRepository.findById(request.getSupplierId())
                .orElseThrow(() -> new RuntimeException("Supplier not found with id: " + request.getSupplierId()));

        User warehouseManager = userRepository.findById(request.getWarehouseManagerId())
                .orElseThrow(() -> new RuntimeException("User not found with id: " + request.getWarehouseManagerId()));

        PurchaseOrder purchaseOrder = purchaseOrderMapper.toEntity(request, supplier, warehouseManager);

        for (PurchaseOrderLineRequest lineRequest : request.getOrderLines()) {
            Product product = productRepository.findById(lineRequest.getProductId())
                    .orElseThrow(() -> new RuntimeException("Product not found with id: " + lineRequest.getProductId()));

            PurchaseOrderLine orderLine = purchaseOrderMapper.toLineEntity(lineRequest, product);
            purchaseOrder.addOrderLine(orderLine);
        }

        PurchaseOrder savedOrder = purchaseOrderRepository.save(purchaseOrder);
        return purchaseOrderMapper.toDTO(savedOrder);
    }

    @Transactional(readOnly = true)
    public List<PurchaseOrderDTO> getAllPurchaseOrders() {
        return purchaseOrderRepository.findAll().stream()
                .map(purchaseOrderMapper::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public PurchaseOrderDTO getPurchaseOrderById(Long id) {
        PurchaseOrder purchaseOrder = purchaseOrderRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Purchase order not found with id: " + id));
        return purchaseOrderMapper.toDTO(purchaseOrder);
    }

    @Transactional
    public PurchaseOrderDTO updatePurchaseOrderStatus(Long id, UpdatePurchaseOrderStatusRequest request) {
        PurchaseOrder purchaseOrder = purchaseOrderRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Purchase order not found with id: " + id));

        PurchaseOrderStatus newStatus = PurchaseOrderStatus.valueOf(request.getStatus());
        purchaseOrder.setStatus(newStatus);

        PurchaseOrder updatedOrder = purchaseOrderRepository.save(purchaseOrder);
        return purchaseOrderMapper.toDTO(updatedOrder);
    }

    @Transactional(readOnly = true)
    public List<PurchaseOrderDTO> getPurchaseOrdersByStatus(String status) {
        PurchaseOrderStatus orderStatus = PurchaseOrderStatus.valueOf(status.toUpperCase());
        return purchaseOrderRepository.findByStatus(orderStatus).stream()
                .map(purchaseOrderMapper::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PurchaseOrderDTO> getPurchaseOrdersBySupplier(Long supplierId) {
        return purchaseOrderRepository.findBySupplierId(supplierId).stream()
                .map(purchaseOrderMapper::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PurchaseOrderDTO> getPurchaseOrdersByWarehouseManager(Long warehouseManagerId) {
        return purchaseOrderRepository.findByWarehouseManagerId(warehouseManagerId).stream()
                .map(purchaseOrderMapper::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional
    public void deletePurchaseOrder(Long id) {
        PurchaseOrder purchaseOrder = purchaseOrderRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Purchase order not found with id: " + id));
        purchaseOrderRepository.delete(purchaseOrder);
    }
}