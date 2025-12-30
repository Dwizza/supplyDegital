package org.example.digitallogisticssupplychainplatform.service;

import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.entity.Inventory;
import org.example.digitallogisticssupplychainplatform.entity.InventoryMovement;
import org.example.digitallogisticssupplychainplatform.entity.MovementType;
import org.example.digitallogisticssupplychainplatform.mapper.InventoryMovementMapper;
import org.example.digitallogisticssupplychainplatform.repository.InventoryMovementRepository;
import org.example.digitallogisticssupplychainplatform.repository.InventoryRepository;
import org.example.digitallogisticssupplychainplatform.service.InventoryMovementService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class InventoryMovementServiceImpl implements InventoryMovementService {

    private final InventoryMovementRepository movementRepository;
    private final InventoryRepository inventoryRepository;
    private final InventoryMovementMapper movementMapper;

    @Override
    @Transactional(readOnly = true)
    public List<InventoryMovementDTO> findAll() {
        return movementRepository.findAllWithDetails().stream()
                .map(movementMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<InventoryMovementDTO> findByInventoryId(Long inventoryId) {
        return movementRepository.findByInventoryId(inventoryId).stream()
                .map(movementMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<InventoryMovementDTO> findByProductId(Long productId) {
        return movementRepository.findByInventoryProductId(productId).stream()
                .map(movementMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<InventoryMovementDTO> findByWarehouseId(Long warehouseId) {
        return movementRepository.findByInventoryWarehouseId(warehouseId).stream()
                .map(movementMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<InventoryMovementDTO> findByType(String type) {
        MovementType movementType = MovementType.valueOf(type.toUpperCase());
        return movementRepository.findByType(movementType).stream()
                .map(movementMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<InventoryMovementDTO> findByDateRange(LocalDateTime startDate, LocalDateTime endDate) {
        return movementRepository.findByDateRange(startDate, endDate).stream()
                .map(movementMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public InventoryMovementDTO findById(Long id) {
        InventoryMovement movement = movementRepository.findByIdWithDetails(id);
        if (movement == null) {
            throw new RuntimeException("Mouvement non trouvé avec l'id: " + id);
        }
        return movementMapper.toDto(movement);
    }

    @Override
    public InventoryMovementDTO createMovement(InventoryMovementDTO movementDTO) {
        Inventory inventory = inventoryRepository.findById(movementDTO.getInventoryId())
                .orElseThrow(() -> new RuntimeException("Inventaire non trouvé avec l'id: " + movementDTO.getInventoryId()));

        if (movementDTO.getQuantity() <= 0) {
            throw new RuntimeException("La quantité doit être positive");
        }

        InventoryMovement movement = movementMapper.toEntity(movementDTO);
        movement.setInventory(inventory);
        movement.setType(MovementType.valueOf(movementDTO.getType().toUpperCase()));

        if (movementDTO.getOccurredAt() == null) {
            movement.setOccurredAt(LocalDateTime.now());
        }

        InventoryMovement saved = movementRepository.save(movement);
        return movementMapper.toDto(saved);
    }



    @Override
    public void deleteMovement(Long id) {
        if (!movementRepository.existsById(id)) {
            throw new RuntimeException("Mouvement non trouvé avec l'id: " + id);
        }
        movementRepository.deleteById(id);
    }
}