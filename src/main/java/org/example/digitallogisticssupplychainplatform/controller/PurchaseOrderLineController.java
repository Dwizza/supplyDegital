package org.example.digitallogisticssupplychainplatform.controller;

import org.example.digitallogisticssupplychainplatform.dto.PurchaseOrderLineDTO;
import org.example.digitallogisticssupplychainplatform.service.PurchaseOrderLineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/purchase-order-lines")
@RequiredArgsConstructor
public class PurchaseOrderLineController {

    private final PurchaseOrderLineService purchaseOrderLineService;

    @GetMapping
    public ResponseEntity<List<PurchaseOrderLineDTO>> getAllOrderLines() {
        List<PurchaseOrderLineDTO> orderLines = purchaseOrderLineService.getAllOrderLines();
        return ResponseEntity.ok(orderLines);
    }

    @GetMapping("/{id}")
    public ResponseEntity<PurchaseOrderLineDTO> getOrderLineById(@PathVariable Long id) {
        PurchaseOrderLineDTO orderLine = purchaseOrderLineService.getOrderLineById(id);
        return ResponseEntity.ok(orderLine);
    }

    @GetMapping("/purchase-order/{purchaseOrderId}")
    public ResponseEntity<List<PurchaseOrderLineDTO>> getOrderLinesByPurchaseOrder(@PathVariable Long purchaseOrderId) {
        List<PurchaseOrderLineDTO> orderLines = purchaseOrderLineService.getOrderLinesByPurchaseOrder(purchaseOrderId);
        return ResponseEntity.ok(orderLines);
    }

    @GetMapping("/product/{productId}")
    public ResponseEntity<List<PurchaseOrderLineDTO>> getOrderLinesByProduct(@PathVariable Long productId) {
        List<PurchaseOrderLineDTO> orderLines = purchaseOrderLineService.getOrderLinesByProduct(productId);
        return ResponseEntity.ok(orderLines);
    }

    @GetMapping("/product/{productId}/pending")
    public ResponseEntity<List<PurchaseOrderLineDTO>> getPendingOrderLinesByProduct(@PathVariable Long productId) {
        List<PurchaseOrderLineDTO> orderLines = purchaseOrderLineService.getPendingOrderLinesByProduct(productId);
        return ResponseEntity.ok(orderLines);
    }

    @GetMapping("/product/{productId}/total-quantity")
    public ResponseEntity<Double> getTotalQuantityOrderedByProduct(@PathVariable Long productId) {
        Double totalQuantity = purchaseOrderLineService.getTotalQuantityOrderedByProduct(productId);
        return ResponseEntity.ok(totalQuantity);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteOrderLine(@PathVariable Long id) {
        purchaseOrderLineService.deleteOrderLine(id);
        return ResponseEntity.noContent().build();
    }
}