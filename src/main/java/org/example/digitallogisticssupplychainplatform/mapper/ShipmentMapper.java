package org.example.digitallogisticssupplychainplatform.mapper;

import org.example.digitallogisticssupplychainplatform.dto.ShipmentCreateDTO;
import org.example.digitallogisticssupplychainplatform.dto.ShipmentDTO;
import org.example.digitallogisticssupplychainplatform.dto.ShipmentUpdateDTO;
import org.example.digitallogisticssupplychainplatform.entity.Carrier;
import org.example.digitallogisticssupplychainplatform.entity.Shipment;
import org.example.digitallogisticssupplychainplatform.entity.ShipmentStatus;
import org.springframework.stereotype.Component;
import java.util.stream.Collectors;

@Component
public class ShipmentMapper {

    public ShipmentDTO toDTO(Shipment shipment) {
        if (shipment == null) return null;

        return ShipmentDTO.builder()
                .id(shipment.getId())
                .trackingNumber(shipment.getTrackingNumber())
                .carrierId(shipment.getCarrier() != null ? shipment.getCarrier().getId() : null)
                .carrierName(shipment.getCarrier() != null ? shipment.getCarrier().getName() : null)
                .plannedDate(shipment.getPlannedDate())
                .shippedDate(shipment.getShippedDate())
                .deliveredDate(shipment.getDeliveredDate())
                .status(shipment.getStatus() != null ? shipment.getStatus().name() : null)
                .description(shipment.getDescription())
                .build();
    }

    public Shipment toEntity(ShipmentCreateDTO dto, Carrier carrier) {
        if (dto == null) return null;

        return Shipment.builder()
                .trackingNumber(dto.getTrackingNumber())
                .carrier(carrier)
                .plannedDate(dto.getPlannedDate())
                .status(ShipmentStatus.valueOf(dto.getStatus()))
                .description(dto.getDescription())
                .build();
    }

    public void updateEntityFromDTO(ShipmentUpdateDTO dto, Shipment shipment, Carrier carrier) {
        if (dto == null || shipment == null) return;

        if (dto.getTrackingNumber() != null) {
            shipment.setTrackingNumber(dto.getTrackingNumber());
        }
        if (carrier != null) {
            shipment.setCarrier(carrier);
        }
        if (dto.getPlannedDate() != null) {
            shipment.setPlannedDate(dto.getPlannedDate());
        }
        if (dto.getShippedDate() != null) {
            shipment.setShippedDate(dto.getShippedDate());
        }
        if (dto.getDeliveredDate() != null) {
            shipment.setDeliveredDate(dto.getDeliveredDate());
        }
        if (dto.getStatus() != null) {
            shipment.setStatus(ShipmentStatus.valueOf(dto.getStatus()));
        }
        if (dto.getDescription() != null) {
            shipment.setDescription(dto.getDescription());
        }
    }
}