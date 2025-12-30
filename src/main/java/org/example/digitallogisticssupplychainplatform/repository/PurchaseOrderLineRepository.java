package org.example.digitallogisticssupplychainplatform.repository;

import org.example.digitallogisticssupplychainplatform.entity.PurchaseOrderLine;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PurchaseOrderLineRepository extends JpaRepository<PurchaseOrderLine, Long> {

    List<PurchaseOrderLine> findByPurchaseOrderId(Long purchaseOrderId);

    List<PurchaseOrderLine> findByProductId(Long productId);

    @Query("SELECT pol FROM PurchaseOrderLine pol WHERE pol.purchaseOrder.status = 'PENDING' AND pol.product.id = :productId")
    List<PurchaseOrderLine> findPendingOrderLinesByProductId(@Param("productId") Long productId);
}