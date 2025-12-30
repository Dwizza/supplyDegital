package org.example.digitallogisticssupplychainplatform.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.entity.ShipmentStatus;
import org.example.digitallogisticssupplychainplatform.service.ShipmentBusinessService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/shipments/business")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class ShipmentBusinessController {

    private final ShipmentBusinessService shipmentBusinessService;


    @GetMapping("/track/{trackingNumber}")
    public ResponseEntity<ShipmentBusinessService.ShipmentTracking> trackShipment(
            @PathVariable String trackingNumber) {

        ShipmentBusinessService.ShipmentTracking tracking =
                shipmentBusinessService.trackShipment(trackingNumber);

        return ResponseEntity.ok(tracking);
    }


    @PostMapping("/{shipmentId}/start-transit")
    public ResponseEntity<StatusUpdateResponse> startTransit(@PathVariable Long shipmentId) {
        shipmentBusinessService.updateStatus(shipmentId, ShipmentStatus.IN_TRANSIT);

        return ResponseEntity.ok(StatusUpdateResponse.builder()
                .shipmentId(shipmentId)
                .newStatus(ShipmentStatus.IN_TRANSIT)
                .message("Expédition en transit")
                .build());
    }

    @PostMapping("/{shipmentId}/deliver")
    public ResponseEntity<StatusUpdateResponse> deliver(@PathVariable Long shipmentId) {
        shipmentBusinessService.updateStatus(shipmentId, ShipmentStatus.DELIVERED);

        return ResponseEntity.ok(StatusUpdateResponse.builder()
                .shipmentId(shipmentId)
                .newStatus(ShipmentStatus.DELIVERED)
                .message(" Expédition livrée")
                .build());
    }


    @Data
    @AllArgsConstructor
    public static class CreateShipmentRequest {
        @NotNull(message = "L'ID du transporteur est obligatoire")
        private Long carrierId;

        @NotBlank(message = "La description est obligatoire")
        private String description;
    }

    @Data
    @lombok.Builder
    public static class StatusUpdateResponse {
        private Long shipmentId;
        private ShipmentStatus newStatus;
        private String message;
    }
}