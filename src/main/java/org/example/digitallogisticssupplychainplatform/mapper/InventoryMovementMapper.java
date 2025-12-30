
package org.example.digitallogisticssupplychainplatform.mapper;

import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.entity.InventoryMovement;
import org.springframework.stereotype.Component;

@Component
public class InventoryMovementMapper {

    public InventoryMovementDTO toDto(InventoryMovement movement) {
        if (movement == null) {
            return null;
        }

        InventoryMovementDTO dto = new InventoryMovementDTO();
        dto.setId(movement.getId());
        dto.setInventoryId(movement.getInventory().getId());
        dto.setType(movement.getType().name());
        dto.setQuantity(movement.getQuantity());
        dto.setOccurredAt(movement.getOccurredAt());
        dto.setReferenceDoc(movement.getReferenceDoc());
        dto.setDescription(movement.getDescription());
        if (movement.getInventory() != null) {
            dto.setProductId(movement.getInventory().getProduct().getId());
            dto.setProductCode(movement.getInventory().getProduct().getCode());
            dto.setProductName(movement.getInventory().getProduct().getName());

            dto.setWarehouseId(movement.getInventory().getWarehouse().getId());
            dto.setWarehouseCode(movement.getInventory().getWarehouse().getCode());
            dto.setWarehouseName(movement.getInventory().getWarehouse().getName());
        }

        return dto;
    }

    public InventoryMovement toEntity(InventoryMovementDTO dto) {
        if (dto == null) {
            return null;
        }

        return InventoryMovement.builder()
                .id(dto.getId())
                .quantity(dto.getQuantity())
                .occurredAt(dto.getOccurredAt())
                .referenceDoc(dto.getReferenceDoc())
                .description(dto.getDescription())
                .build();
    }
}