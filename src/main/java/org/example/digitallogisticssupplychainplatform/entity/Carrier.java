package org.example.digitallogisticssupplychainplatform.entity;


import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalTime;

@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "carriers")
@Getter
@Setter
public class Carrier {
    @Id
    @GeneratedValue(strategy =GenerationType.IDENTITY)

    private Long id;
    @Column(nullable = false)
    private String code ;
    @Column(nullable = false)
    private String name;
    @Column(nullable = false)
    private String contactEmail;
    @Column(nullable = false)
    private String contactPhone;
    @Column(nullable = false)
    private BigDecimal baseShippingRate;
    @Column(nullable = false)
    private Integer maxDailyCapacity;
    @Column(nullable = false)
    private Integer currentDailyShipments;
    @Column(nullable = false)
    private LocalTime cutOffTime;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CarrierStatus status;
}
