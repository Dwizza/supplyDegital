package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PurchaseOrderDTO {
    private Long id;
    private Long supplierId;
    private String supplierName;
    private Long warehouseManagerId;
    private String warehouseManagerName;
    private String status;
    private LocalDateTime createdAt;
    private LocalDateTime expectedDelivery;
    private List<PurchaseOrderLineDTO> orderLines;
}