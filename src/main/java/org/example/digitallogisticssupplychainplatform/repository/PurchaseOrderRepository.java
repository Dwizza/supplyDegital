package org.example.digitallogisticssupplychainplatform.repository;

import org.example.digitallogisticssupplychainplatform.entity.PurchaseOrder;
import org.example.digitallogisticssupplychainplatform.entity.PurchaseOrderStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface PurchaseOrderRepository extends JpaRepository<PurchaseOrder, Long> {

    List<PurchaseOrder> findByStatus(PurchaseOrderStatus status);

    List<PurchaseOrder> findBySupplierId(Long supplierId);

    List<PurchaseOrder> findByWarehouseManagerId(Long warehouseManagerId);

    List<PurchaseOrder> findByExpectedDeliveryBetween(LocalDateTime start, LocalDateTime end);

    @Query("SELECT po FROM PurchaseOrder po WHERE po.expectedDelivery < :date AND po.status IN :statuses")
    List<PurchaseOrder> findOverdueOrders(@Param("date") LocalDateTime date,
                                          @Param("statuses") List<PurchaseOrderStatus> statuses);

    List<PurchaseOrder> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end);
}