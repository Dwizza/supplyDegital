package org.example.digitallogisticssupplychainplatform.mapper;

import org.example.digitallogisticssupplychainplatform.dto.*;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Component
public class PurchaseOrderMapper {

    public PurchaseOrderDTO toDTO(PurchaseOrder purchaseOrder) {
        if (purchaseOrder == null) {
            return null;
        }

        return PurchaseOrderDTO.builder()
                .id(purchaseOrder.getId())
                .supplierId(purchaseOrder.getSupplier() != null ? purchaseOrder.getSupplier().getId() : null)
                .supplierName(purchaseOrder.getSupplier() != null ? purchaseOrder.getSupplier().getName() : null)
                .warehouseManagerId(purchaseOrder.getWarehouseManager() != null ? purchaseOrder.getWarehouseManager().getId() : null)
                .warehouseManagerName(purchaseOrder.getWarehouseManager() != null ? purchaseOrder.getWarehouseManager().getUsername() : null)
                .status(purchaseOrder.getStatus().name())
                .createdAt(purchaseOrder.getCreatedAt())
                .expectedDelivery(purchaseOrder.getExpectedDelivery())
                .orderLines(purchaseOrder.getOrderLines().stream()
                        .map(this::toLineDTO)
                        .collect(Collectors.toList()))
                .build();
    }

    public PurchaseOrderLineDTO toLineDTO(PurchaseOrderLine orderLine) {
        if (orderLine == null) {
            return null;
        }

        return PurchaseOrderLineDTO.builder()
                .id(orderLine.getId())
                .productId(orderLine.getProduct() != null ? orderLine.getProduct().getId() : null)
                .productName(orderLine.getProduct() != null ? orderLine.getProduct().getName() : null)
                .productSku(orderLine.getProduct() != null ? orderLine.getProduct().getName() : null)
                .quantity(orderLine.getQuantity())
                .unitPrice(orderLine.getUnitPrice())
                .lineTotal(orderLine.getLineTotal())
                .build();
    }

    public PurchaseOrder toEntity(CreatePurchaseOrderRequest request, Supplier supplier, User warehouseManager) {
        if (request == null) {
            return null;
        }

        return PurchaseOrder.builder()
                .supplier(supplier)
                .warehouseManager(warehouseManager)
                .expectedDelivery(request.getExpectedDelivery())
                .build();
    }

    public PurchaseOrderLine toLineEntity(PurchaseOrderLineRequest request, Product product) {
        if (request == null) {
            return null;
        }

        return PurchaseOrderLine.builder()
                .product(product)
                .quantity(request.getQuantity())
                .unitPrice(request.getUnitPrice())
                .build();
    }
}