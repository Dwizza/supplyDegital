package org.example.digitallogisticssupplychainplatform.service;

// InventoryServiceImpl.java

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.dto.InventoryDTO;
import org.example.digitallogisticssupplychainplatform.exception.ResourceNotFoundException;
import org.example.digitallogisticssupplychainplatform.mapper.InventoryMapper;
import org.example.digitallogisticssupplychainplatform.repository.InventoryRepository;
import org.example.digitallogisticssupplychainplatform.repository.ProductRepository;
import org.example.digitallogisticssupplychainplatform.repository.WareHouseRepository;
import org.example.digitallogisticssupplychainplatform.service.InventoryService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
@Builder
@RequiredArgsConstructor
@Service
@Transactional
public class InventoryServiceImpl implements InventoryService {

    private final InventoryRepository inventoryRepository;
    private final WareHouseRepository warehouseRepository;
    private final ProductRepository productRepository;
    private final InventoryMapper inventoryMapper;


    @Override
    @Transactional(readOnly = true)
    public List<InventoryDTO> findAll() {
        return inventoryRepository.findAllWithWarehouse().stream()
                .map(inventoryMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<InventoryDTO> findByWarehouseId(Long warehouseId) {
        return inventoryRepository.findByWarehouseId(warehouseId).stream()
                .map(inventoryMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<InventoryDTO> findById(Long id) {
        return inventoryRepository.findById(id)
                .map(inventoryMapper::toDto);
    }

    @Override
    public InventoryDTO save(InventoryDTO inventoryDTO) {
        WareHouse warehouse = warehouseRepository.findById(inventoryDTO.getWarehouseId())
                .orElseThrow(() -> new RuntimeException("Entrepôt non trouvé avec l'id: " + inventoryDTO.getWarehouseId()));
        Product product = productRepository.findById(inventoryDTO.getProductId())
                .orElseThrow(()->new RuntimeException("Product non trouve avec lid"));
        Inventory inventory = inventoryMapper.toEntity(inventoryDTO);
        inventory.setWarehouse(warehouse);
        inventory.setProduct(product);

        if (inventory.getQtyOnHand() == null) {
            inventory.setQtyOnHand(0);
        }
        if (inventory.getQtyReserved() == null) {
            inventory.setQtyReserved(0);
        }

        Inventory saved = inventoryRepository.save(inventory);
        return inventoryMapper.toDto(saved);
    }

    @Override
    public InventoryDTO update(Long id, InventoryDTO inventoryDTO) {
        return inventoryRepository.findById(id)
                .map(existingInventory -> {
                    WareHouse warehouse = warehouseRepository.findById(inventoryDTO.getWarehouseId())
                            .orElseThrow(() -> new RuntimeException("Entrepôt non trouvé avec l'id: " + inventoryDTO.getWarehouseId()));

                    existingInventory.setQtyOnHand(inventoryDTO.getQtyOnHand());
                    existingInventory.setQtyReserved(inventoryDTO.getQtyReserved());
                    existingInventory.setWarehouse(warehouse);

                    Inventory updated = inventoryRepository.save(existingInventory);
                    return inventoryMapper.toDto(updated);
                })
                .orElseThrow(() -> new RuntimeException("Inventaire non trouvé avec l'id: " + id));
    }

    @Override
    public void delete(Long id) {
        Inventory inventory = inventoryRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Inventory not found with id: " + id));

        if (inventory.getQtyReserved() > 0) {
            throw new RuntimeException("Cannot delete inventory with reserved stock");
        }

        inventoryRepository.deleteById(id);
    }

    @Override
    public InventoryDTO updateQuantities(Long id, Integer qtyOnHand, Integer qtyReserved) {
        return inventoryRepository.findById(id)
                .map(inventory -> {
                    inventory.setQtyOnHand(qtyOnHand);
                    inventory.setQtyReserved(qtyReserved);

                    Inventory updated = inventoryRepository.save(inventory);
                    return inventoryMapper.toDto(updated);
                })
                .orElseThrow(() -> new RuntimeException("Inventaire non trouvé avec l'id: " + id));
    }

}
