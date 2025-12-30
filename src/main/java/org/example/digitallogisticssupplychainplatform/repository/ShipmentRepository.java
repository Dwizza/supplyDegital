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
public interface ShipmentRepository extends JpaRepository<Shipment, Long> {

    Optional<Shipment> findByTrackingNumber(String trackingNumber);

    boolean existsByTrackingNumber(String trackingNumber);


    List<Shipment> findByCarrierId(Long carrierId);

    List<Shipment> findByStatus(ShipmentStatus status);


    @Query("SELECT s FROM Shipment s WHERE s.status = 'PLANNED'")
    List<Shipment> findPlannedShipments();

    @Query("SELECT s FROM Shipment s WHERE s.carrier.id = :carrierId AND s.status = :status")
    List<Shipment> findByCarrierIdAndStatus(
            @Param("carrierId") Long carrierId,
            @Param("status") ShipmentStatus status
    );

    @Query("SELECT s FROM Shipment s WHERE s.plannedDate BETWEEN :startDate AND :endDate")
    List<Shipment> findByPlannedDateBetween(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );

    @Query("SELECT s FROM Shipment s WHERE s.shippedDate IS NULL")
    List<Shipment> findPendingShipments();

    @Query("SELECT s FROM Shipment s WHERE s.shippedDate IS NOT NULL AND s.deliveredDate IS NULL")
    List<Shipment> findInTransitShipments();

    @Query("SELECT s FROM Shipment s WHERE s.deliveredDate IS NOT NULL")
    List<Shipment> findDeliveredShipments();


}