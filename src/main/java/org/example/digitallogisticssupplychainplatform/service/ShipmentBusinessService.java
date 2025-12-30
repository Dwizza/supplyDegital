package org.example.digitallogisticssupplychainplatform.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.exception.BusinessException;
import org.example.digitallogisticssupplychainplatform.exception.ResourceNotFoundException;
import org.example.digitallogisticssupplychainplatform.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class ShipmentBusinessService {

    private final ShipmentRepository shipmentRepository;
    private final CarrierRepository carrierRepository;


    public void updateStatus(Long shipmentId, ShipmentStatus newStatus) {
        Shipment shipment = shipmentRepository.findById(shipmentId)
                .orElseThrow(() -> new ResourceNotFoundException("Expédition introuvable: " + shipmentId));

        ShipmentStatus currentStatus = shipment.getStatus();

        validateTransition(currentStatus, newStatus);
        switch (newStatus) {
            case IN_TRANSIT:
                shipment.setShippedDate(LocalDateTime.now());
                log.info("Expédition {} en transit", shipmentId);
                break;

            case DELIVERED:
                shipment.setDeliveredDate(LocalDateTime.now());
                log.info("Expédition {} livrée", shipmentId);
                break;
        }

        shipment.setStatus(newStatus);
        shipmentRepository.save(shipment);
    }

    public ShipmentTracking trackShipment(String trackingNumber) {
        Shipment shipment = shipmentRepository.findByTrackingNumber(trackingNumber)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Aucune expédition trouvée: " + trackingNumber));

        return ShipmentTracking.builder()
                .trackingNumber(trackingNumber)
                .carrierName(shipment.getCarrier().getName())
                .status(shipment.getStatus())
                .plannedDate(shipment.getPlannedDate())
                .shippedDate(shipment.getShippedDate())
                .deliveredDate(shipment.getDeliveredDate())
                .description(shipment.getDescription())
                .build();
    }

    private void validateTransition(ShipmentStatus current, ShipmentStatus next) {
        boolean valid = false;

        switch (current) {
            case PLANNED:
                valid = (next == ShipmentStatus.IN_TRANSIT || next == ShipmentStatus.CANCELLED);
                break;
            case IN_TRANSIT:
                valid = (next == ShipmentStatus.DELIVERED);
                break;
            case DELIVERED:
            case CANCELLED:
                valid = false;
                break;
        }

        if (!valid) {
            throw new BusinessException(
                    String.format("Transition invalide de %s vers %s", current, next));
        }
    }





    @Data
    @Builder
    public static class ShipmentCreationResult {
        private Long shipmentId;
        private String trackingNumber;
        private String carrierName;
        private ShipmentStatus status;
        private String message;
    }

    @Data
    @Builder
    public static class ShipmentTracking {
        private String trackingNumber;
        private String carrierName;
        private ShipmentStatus status;
        private LocalDateTime plannedDate;
        private LocalDateTime shippedDate;
        private LocalDateTime deliveredDate;
        private String description;
    }
}