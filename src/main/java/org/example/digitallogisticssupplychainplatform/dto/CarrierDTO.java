package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;
import org.example.digitallogisticssupplychainplatform.entity.CarrierStatus;

import java.math.BigDecimal;
import java.time.LocalTime;
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class CarrierDTO {
    private String code ;
    private String name;
    private String contactEmail;
    private String contactPhone;
    private BigDecimal baseShippingRate;
    private Integer maxDailyCapacity;
    private Integer currentDailyShipments;
    private LocalTime cutOffTime;
    private CarrierStatus status;
}
