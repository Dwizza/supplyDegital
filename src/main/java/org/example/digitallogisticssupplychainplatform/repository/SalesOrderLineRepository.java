package org.example.digitallogisticssupplychainplatform.repository;

import org.example.digitallogisticssupplychainplatform.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface SalesOrderLineRepository extends JpaRepository<SalesOrderLine, Long> {

    List<SalesOrderLine> findBySalesOrderId(Long salesOrderId);

    List<SalesOrderLine> findByProductId(Long productId);

    @Query("SELECT sol FROM SalesOrderLine sol WHERE sol.backordered = true")
    List<SalesOrderLine> findBackorderedLines();

    @Query("SELECT sol FROM SalesOrderLine sol WHERE sol.salesOrder.id = :orderId AND sol.product.id = :productId")
    Optional<SalesOrderLine> findByOrderIdAndProductId(
            @Param("orderId") Long orderId,
            @Param("productId") Long productId
    );

    @Query("SELECT SUM(sol.quantity) FROM SalesOrderLine sol WHERE sol.product.id = :productId")
    Long getTotalQuantityByProduct(@Param("productId") Long productId);

    @Query("SELECT sol FROM SalesOrderLine sol WHERE sol.salesOrder.client.id = :clientId")
    List<SalesOrderLine> findByClientId(@Param("clientId") Long clientId);

    @Query("SELECT COUNT(sol) FROM SalesOrderLine sol WHERE sol.salesOrder.id = :orderId")
    Long countBySalesOrderId(@Param("orderId") Long orderId);
}

