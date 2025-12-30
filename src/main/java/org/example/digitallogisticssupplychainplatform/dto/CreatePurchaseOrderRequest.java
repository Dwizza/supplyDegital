package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreatePurchaseOrderRequest {
    private Long supplierId;
    private Long warehouseManagerId;
    private LocalDateTime expectedDelivery;
    private List<PurchaseOrderLineRequest> orderLines;
}