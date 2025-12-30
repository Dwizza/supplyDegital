package org.example.digitallogisticssupplychainplatform.repository;

import org.example.digitallogisticssupplychainplatform.entity.InventoryMovement;
import org.example.digitallogisticssupplychainplatform.entity.MovementType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface InventoryMovementRepository extends JpaRepository<InventoryMovement, Long> {

    List<InventoryMovement> findByInventoryId(Long inventoryId);
    List<InventoryMovement> findByInventoryProductId(Long productId);
    List<InventoryMovement> findByInventoryWarehouseId(Long warehouseId);
    List<InventoryMovement> findByType(MovementType type);

    @Query("SELECT im FROM InventoryMovement im WHERE im.occurredAt BETWEEN :startDate AND :endDate")
    List<InventoryMovement> findByDateRange(@Param("startDate") LocalDateTime startDate,
                                            @Param("endDate") LocalDateTime endDate);

    @Query("SELECT im FROM InventoryMovement im JOIN FETCH im.inventory i JOIN FETCH i.product JOIN FETCH i.warehouse WHERE im.id = :id")
    InventoryMovement findByIdWithDetails(@Param("id") Long id);

    @Query("SELECT im FROM InventoryMovement im JOIN FETCH im.inventory i JOIN FETCH i.product JOIN FETCH i.warehouse")
    List<InventoryMovement> findAllWithDetails();
}