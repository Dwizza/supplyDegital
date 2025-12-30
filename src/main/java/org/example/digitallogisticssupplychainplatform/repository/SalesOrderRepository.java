package org.example.digitallogisticssupplychainplatform.repository;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface SalesOrderRepository extends JpaRepository<SalesOrder, Long> {

    List<SalesOrder> findByClientId(Long clientId);

    @Query("SELECT so FROM SalesOrder so WHERE so.createdAt BETWEEN :startDate AND :endDate")
    List<SalesOrder> findByCreatedAtBetween(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );

    @Query("SELECT so FROM SalesOrder so WHERE so.reservedAt IS NULL")
    List<SalesOrder> findPendingOrders();

    @Query("SELECT so FROM SalesOrder so WHERE so.reservedAt IS NOT NULL AND so.shippedAt IS NULL")
    List<SalesOrder> findReservedOrders();

    @Query("SELECT so FROM SalesOrder so WHERE so.shippedAt IS NOT NULL AND so.deliveredAt IS NULL")
    List<SalesOrder> findShippedOrders();

    @Query("SELECT so FROM SalesOrder so WHERE so.deliveredAt IS NOT NULL")
    List<SalesOrder> findDeliveredOrders();

    @Query("SELECT so FROM SalesOrder so JOIN FETCH so.orderLines WHERE so.id = :id")
    Optional<SalesOrder> findByIdWithLines(@Param("id") Long id);

    @Query("SELECT COUNT(so) FROM SalesOrder so WHERE so.client.id = :clientId")
    Long countByClientId(@Param("clientId") Long clientId);

    @Query("SELECT so FROM SalesOrder so JOIN so.orderLines ol WHERE ol.backordered = true")
    List<SalesOrder> findOrdersWithBackorders();
}
