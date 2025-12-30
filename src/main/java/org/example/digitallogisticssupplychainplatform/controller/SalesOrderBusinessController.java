package org.example.digitallogisticssupplychainplatform.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.service.SalesOrderBusinessService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/sales-orders/business")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class SalesOrderBusinessController {

    private final SalesOrderBusinessService salesOrderBusinessService;


    @PostMapping("/{orderId}/reserve")
    public ResponseEntity<SalesOrderBusinessService.ReservationResult> reserveOrder(
            @PathVariable Long orderId,
            @RequestParam Long warehouseId) {

        SalesOrderBusinessService.ReservationResult result =
                salesOrderBusinessService.reserveOrder(orderId, warehouseId);

        return ResponseEntity.ok(result);
    }

    @GetMapping("/{orderId}/check")
    public ResponseEntity<SalesOrderBusinessService.AvailabilityCheck> checkAvailability(
            @PathVariable Long orderId,
            @RequestParam Long warehouseId) {

        SalesOrderBusinessService.AvailabilityCheck result =
                salesOrderBusinessService.checkAvailability(orderId, warehouseId);

        return ResponseEntity.ok(result);
    }

    @PostMapping("/{orderId}/ship")
    public ResponseEntity<SalesOrderBusinessService.ShipmentResult> shipOrder(
            @PathVariable Long orderId,
            @RequestParam Long warehouseId) {

        SalesOrderBusinessService.ShipmentResult result =
                salesOrderBusinessService.shipOrder(orderId, warehouseId);

        return ResponseEntity.ok(result);
    }


    @PostMapping("/{orderId}/deliver")
    public ResponseEntity<DeliveryResponse> deliverOrder(@PathVariable Long orderId) {
        salesOrderBusinessService.deliverOrder(orderId);

        return ResponseEntity.ok(DeliveryResponse.builder()
                .orderId(orderId)
                .message("✓ Commande livrée avec succès")
                .build());
    }

    @PostMapping("/{orderId}/cancel")
    public ResponseEntity<SalesOrderBusinessService.CancellationResult> cancelOrder(
            @PathVariable Long orderId,
            @Valid @RequestBody CancelRequest request,@RequestParam Long warehouseId) {

        SalesOrderBusinessService.CancellationResult result =
                salesOrderBusinessService.cancelOrder(orderId, request.getReason(),warehouseId);

        return ResponseEntity.ok(result);
    }



    @Data
    @AllArgsConstructor
    public static class CancelRequest {
        @NotBlank(message = "La raison est obligatoire")
        private String reason;
    }

    @Data
    @lombok.Builder
    public static class DeliveryResponse {
        private Long orderId;
        private String message;
    }
}