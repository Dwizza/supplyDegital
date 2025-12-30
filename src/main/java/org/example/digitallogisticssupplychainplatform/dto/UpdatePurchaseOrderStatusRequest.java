package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UpdatePurchaseOrderStatusRequest {
    private String status;
}