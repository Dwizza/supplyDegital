package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;
import java.math.BigDecimal;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PurchaseOrderLineRequest {
    private Long productId;
    private Integer quantity;
    private BigDecimal unitPrice;
}