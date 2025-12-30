package org.example.digitallogisticssupplychainplatform.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "shipments")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Shipment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String trackingNumber;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "carrier_id", nullable = false)
    private Carrier carrier;

    @Column(nullable = false)
    private LocalDateTime plannedDate;

    @Column
    private LocalDateTime shippedDate;

    @Column
    private LocalDateTime deliveredDate;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private ShipmentStatus status;

    @Column(length = 500)
    private String description;


    @PrePersist
    protected void onCreate() {
        if (plannedDate == null) {
            plannedDate = LocalDateTime.now();
        }
    }
}
