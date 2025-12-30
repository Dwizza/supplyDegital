package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import java.time.LocalDateTime;
import java.util.List;

public interface InventoryMovementService {
    List<InventoryMovementDTO> findAll();
    List<InventoryMovementDTO> findByInventoryId(Long inventoryId);
    List<InventoryMovementDTO> findByProductId(Long productId);
    List<InventoryMovementDTO> findByWarehouseId(Long warehouseId);
    List<InventoryMovementDTO> findByType(String type);
    List<InventoryMovementDTO> findByDateRange(LocalDateTime startDate, LocalDateTime endDate);
    InventoryMovementDTO findById(Long id);
    InventoryMovementDTO createMovement(InventoryMovementDTO movementDTO);
    void deleteMovement(Long id);
}