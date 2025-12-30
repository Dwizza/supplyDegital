package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class InventoryDTO {
    private Long id;
    private Integer qtyOnHand;
    private Integer qtyReserved;
    private Long warehouseId;
    private String warehouseCode;
    private String warehouseName;
    private Long productId;
    private String productDescription;
    private String productName;
    private String productCode;
}