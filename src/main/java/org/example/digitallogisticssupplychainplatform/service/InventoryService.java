package org.example.digitallogisticssupplychainplatform.service;



import org.example.digitallogisticssupplychainplatform.dto.InventoryDTO;
import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.entity.InventoryMovement;

import java.util.List;
import java.util.Optional;

public interface InventoryService {
    List<InventoryDTO> findAll();
    List<InventoryDTO> findByWarehouseId(Long warehouseId);
    Optional<InventoryDTO> findById(Long id);
    InventoryDTO save(InventoryDTO inventoryDTO);
    InventoryDTO update(Long id, InventoryDTO inventoryDTO);
    void delete(Long id);
    InventoryDTO updateQuantities(Long id, Integer qtyOnHand, Integer qtyReserved);


}
