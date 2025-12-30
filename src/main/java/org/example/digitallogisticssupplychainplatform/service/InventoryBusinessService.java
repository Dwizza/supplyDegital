package org.example.digitallogisticssupplychainplatform.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.digitallogisticssupplychainplatform.dto.InventoryDTO;
import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.exception.BusinessException;
import org.example.digitallogisticssupplychainplatform.exception.StockUnavailableException;
import org.example.digitallogisticssupplychainplatform.mapper.InventoryMapper;
import org.example.digitallogisticssupplychainplatform.repository.InventoryRepository;
import org.example.digitallogisticssupplychainplatform.repository.ProductRepository;
import org.example.digitallogisticssupplychainplatform.repository.WareHouseRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class InventoryBusinessService {

    private final InventoryRepository inventoryRepository;
    private final ProductRepository productRepository;
    private final WareHouseRepository warehouseRepository;
    private final InventoryMovementService movementService;
    private final InventoryMapper inventoryMapper;

    public Integer calculateAvailableQty(Long inventoryId) {
        Inventory inventory = inventoryRepository.findById(inventoryId)
                .orElseThrow(() -> new BusinessException("Inventaire introuvable"));

        return calculateAvailable(inventory);
    }

    private Integer calculateAvailable(Inventory inventory) {
        return inventory.getQtyOnHand() - inventory.getQtyReserved();
    }


    public void reserveStock(Long productId, Long warehouseId, Integer quantity, String referenceDoc) {
        if (quantity <= 0) {
            throw new BusinessException("La quantité à réserver doit être positive");
        }

        Inventory inventory = getOrCreateInventory(productId, warehouseId);
        Integer available = calculateAvailable(inventory);

        if (available > 0) {
            Integer toReserve = Math.min(available, quantity);
            inventory.setQtyReserved(inventory.getQtyReserved() + toReserve);
            inventoryRepository.save(inventory);
            log.info("Stock réservé: {} unités du produit {} dans l'entrepôt {} - Référence: {}",
                    toReserve, productId, warehouseId, referenceDoc);
        }


        if (available < quantity) {
            log.warn("Stock insuffisant pour {}: disponible {} demandé {}",
                    productId, available, quantity);

        }
    }

    public void releaseReservation(Long productId, Long warehouseId, Integer quantity, String referenceDoc) {
        if (quantity <= 0) {
            throw new BusinessException("La quantité à libérer doit être positive");
        }

        Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(productId, warehouseId);
        if (inventory == null) {
            throw new BusinessException("Inventaire introuvable pour libération");
        }

        if (inventory.getQtyReserved() < quantity) {
            throw new BusinessException(
                    String.format("Impossible de libérer %d unités : seulement %d réservées",
                            quantity, inventory.getQtyReserved())
            );
        }

        inventory.setQtyReserved(inventory.getQtyReserved() - quantity);
        inventoryRepository.save(inventory);

        log.info("Réservation libérée: {} unités du produit {} dans l'entrepôt {} - Référence: {}",
                quantity, productId, warehouseId, referenceDoc);
    }

    public InventoryMovementDTO recordInbound(Long productId, Long warehouseId, Integer quantity,
                                              String referenceDoc, String description) {
        validatePositiveQuantity(quantity);
        validateProductAndWarehouse(productId, warehouseId);

        Inventory inventory = getOrCreateInventory(productId, warehouseId);

        inventory.setQtyOnHand(inventory.getQtyOnHand() + quantity);
        InventoryMovementDTO movementDTO = InventoryMovementDTO.builder()
                .inventoryId(inventory.getId())
                .type(MovementType.INBOUND.name())
                .quantity(quantity)
                .occurredAt(LocalDateTime.now())
                .referenceDoc(referenceDoc)
                .description(description)
                .build();

        return movementService.createMovement(movementDTO);
    }


    public InventoryMovementDTO recordOutbound(Long productId, Long warehouseId, Integer quantity,
                                               String referenceDoc, String description) {
        validatePositiveQuantity(quantity);

        Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(productId, warehouseId);
        if (inventory == null) {
            throw new BusinessException("Inventaire introuvable pour sortie");
        }


        Integer available = calculateAvailable(inventory);
        if (quantity > available) {
            throw new StockUnavailableException(
                    String.format("Stock insuffisant pour sortie. Disponible: %d, Demandé: %d",
                            available, quantity)
            );
        }
        inventory.setQtyOnHand(inventory.getQtyOnHand() - quantity);
        InventoryMovementDTO movementDTO = InventoryMovementDTO.builder()
                .inventoryId(inventory.getId())
                .type(MovementType.OUTBOUND.name())
                .quantity(quantity)
                .occurredAt(LocalDateTime.now())
                .referenceDoc(referenceDoc)
                .description(description)
                .build();

        InventoryMovementDTO result = movementService.createMovement(movementDTO);
        if (inventory.getQtyReserved() >= quantity) {
            inventory.setQtyReserved(inventory.getQtyReserved() - quantity);
            inventoryRepository.save(inventory);
            log.info("Réservation automatiquement libérée lors de l'expédition: {} unités", quantity);
        }

        return result;
    }

    public InventoryMovementDTO recordAdjustment(Long productId, Long warehouseId, Integer adjustmentQty,
                                                 String referenceDoc, String reason) {
        if (adjustmentQty == 0) {
            throw new BusinessException("L'ajustement ne peut pas être nul");
        }

        Inventory inventory = getOrCreateInventory(productId, warehouseId);

        Integer newQtyOnHand = inventory.getQtyOnHand() + adjustmentQty;
        if (newQtyOnHand < inventory.getQtyReserved()) {
            throw new BusinessException(
                    String.format("Ajustement impossible: le stock physique (%d) ne peut pas être inférieur au stock réservé (%d)",
                            newQtyOnHand, inventory.getQtyReserved())
            );
        }

        InventoryMovementDTO movementDTO = InventoryMovementDTO.builder()
                .inventoryId(inventory.getId())
                .type(MovementType.ADJUSTMENT.name())
                .quantity(adjustmentQty)
                .occurredAt(LocalDateTime.now())
                .referenceDoc(referenceDoc)
                .description(reason)
                .build();

        return movementService.createMovement(movementDTO);
    }

    public List<AllocationResult> allocateFromMultipleWarehouses(Long productId, Integer totalQuantity,
                                                                 List<Long> warehouseIdsByPriority) {
        List<AllocationResult> allocations = new ArrayList<>();
        Integer remainingQty = totalQuantity;

        for (Long warehouseId : warehouseIdsByPriority) {
            if (remainingQty <= 0) break;

            Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(productId, warehouseId);
            if (inventory == null) continue;

            Integer available = calculateAvailable(inventory);
            if (available > 0) {
                Integer allocatedQty = Math.min(available, remainingQty);

                allocations.add(AllocationResult.builder()
                        .warehouseId(warehouseId)
                        .productId(productId)
                        .allocatedQuantity(allocatedQty)
                        .inventoryId(inventory.getId())
                        .build());

                remainingQty -= allocatedQty;
            }
        }

        if (remainingQty > 0) {
            log.warn("Allocation partielle: {} unités manquantes pour le produit {}", remainingQty, productId);
        }

        return allocations;
    }

    public boolean isOutOfStock(Long productId, Long warehouseId) {
        Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(productId, warehouseId);
        if (inventory == null) return true;

        return calculateAvailable(inventory) <= 0;
    }


    private Inventory getOrCreateInventory(Long productId, Long warehouseId) {
        Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(productId, warehouseId);

        if (inventory == null) {
            Product product = productRepository.findById(productId)
                    .orElseThrow(() -> new BusinessException("Produit introuvable"));
            WareHouse warehouse = warehouseRepository.findById(warehouseId)
                    .orElseThrow(() -> new BusinessException("Entrepôt introuvable"));

            inventory = Inventory.builder()
                    .product(product)
                    .warehouse(warehouse)
                    .qtyOnHand(0)
                    .qtyReserved(0)
                    .build();

            inventory = inventoryRepository.save(inventory);
            log.info("Nouvel inventaire créé: Produit {} - Entrepôt {}", productId, warehouseId);
        }

        return inventory;
    }

    private void validatePositiveQuantity(Integer quantity) {
        if (quantity == null || quantity <= 0) {
            throw new BusinessException("La quantité doit être positive");
        }
    }

    private void validateProductAndWarehouse(Long productId, Long warehouseId) {
        if (!productRepository.existsById(productId)) {
            throw new BusinessException("Produit introuvable: " + productId);
        }
        if (!warehouseRepository.existsById(warehouseId)) {
            throw new BusinessException("Entrepôt introuvable: " + warehouseId);
        }
    }

    @lombok.Data
    @lombok.Builder
    public static class AllocationResult {
        private Long warehouseId;
        private Long productId;
        private Long inventoryId;
        private Integer allocatedQuantity;
    }
}