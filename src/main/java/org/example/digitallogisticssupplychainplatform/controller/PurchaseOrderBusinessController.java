package org.example.digitallogisticssupplychainplatform.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.service.PurchaseOrderBusinessService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api/purchase-orders/business")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class PurchaseOrderBusinessController {

    private final PurchaseOrderBusinessService purchaseOrderBusinessService;


    @PostMapping("/{poId}/receive-full")
    public ResponseEntity<?> receiveFullOrder(
            @PathVariable Long poId,
            @RequestParam Long warehouseId) {
        try {
            PurchaseOrderBusinessService.ReceiptResult result =
                    purchaseOrderBusinessService.receiveFullOrder(poId, warehouseId);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }


    @PostMapping("/{poId}/approve")
    public ResponseEntity<?> approvePurchaseOrder(@PathVariable Long poId) {
        try {
            PurchaseOrderBusinessService.ApprovalResult result =
                    purchaseOrderBusinessService.approvePurchaseOrder(poId);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/{poId}/cancel")
    public ResponseEntity<?> cancelPurchaseOrder(
            @PathVariable Long poId,
            @Valid @RequestBody CancellationRequest request) {
        try {
            PurchaseOrderBusinessService.CancellationResult result =
                    purchaseOrderBusinessService.cancelPurchaseOrder(poId, request.getReason());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @GetMapping("/{poId}/reception-status")
    public ResponseEntity<?> checkReceptionStatus(@PathVariable Long poId) {
        try {
            PurchaseOrderBusinessService.ReceptionStatus result =
                    purchaseOrderBusinessService.checkReceptionStatus(poId);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }


    @GetMapping("/{poId}/stock-availability")
    public ResponseEntity<?> getStockAvailability(
            @PathVariable Long poId,
            @RequestParam Long warehouseId) {
        try {
            PurchaseOrderBusinessService.StockAvailabilityForPO result =
                    purchaseOrderBusinessService.getStockAvailability(poId, warehouseId);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @Data
    public static class CancellationRequest {
        @NotBlank(message = "La raison d'annulation est obligatoire")
        private String reason;
    }
}