package org.example.digitallogisticssupplychainplatform.repository;

import org.example.digitallogisticssupplychainplatform.entity.Inventory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface InventoryRepository extends JpaRepository<Inventory, Long> {
    List<Inventory> findByWarehouseId(Long warehouseId);

    @Query("SELECT i FROM Inventory i WHERE i.warehouse.id = :warehouseId AND i.id = :inventoryId")
    Optional<Inventory> findByWarehouseIdAndId(@Param("warehouseId") Long warehouseId,
                                               @Param("inventoryId") Long inventoryId);

    @Query("SELECT SUM(i.qtyOnHand) FROM Inventory i WHERE i.warehouse.id = :warehouseId")
    Integer getTotalQtyOnHandByWarehouse(@Param("warehouseId") Long warehouseId);

    @Query("SELECT i FROM Inventory i LEFT JOIN FETCH i.warehouse")
    List<Inventory> findAllWithWarehouse();
    @Query("SELECT i FROM Inventory i " +
            "LEFT JOIN FETCH i.warehouse " +
            "LEFT JOIN FETCH i.product " +
            "WHERE i.product.id = :productId AND i.warehouse.id = :warehouseId")
    Inventory findByProductIdAndWarehouseId(@Param("productId") Long productId,
                                            @Param("warehouseId") Long warehouseId);

}