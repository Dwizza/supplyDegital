
package org.example.digitallogisticssupplychainplatform.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InventoryMovementDTO {
    private Long id;
    private Long inventoryId;
    private String type;
    private Integer quantity;
    private LocalDateTime occurredAt;
    private String referenceDoc;
    private String description;
    private Long productId;
    private String productCode;
    private String productName;
    private Long warehouseId;
    private String warehouseCode;
    private String warehouseName;
}