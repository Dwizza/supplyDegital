package org.example.digitallogisticssupplychainplatform.mapper;

import org.example.digitallogisticssupplychainplatform.dto.SalesOrderLineCreateDTO;
import org.example.digitallogisticssupplychainplatform.dto.SalesOrderLineDTO;
import org.example.digitallogisticssupplychainplatform.dto.SalesOrderLineUpdateDTO;
import org.example.digitallogisticssupplychainplatform.entity.SalesOrderLine;
import org.springframework.stereotype.Component;

@Component
public class SalesOrderLineMapper {

    public SalesOrderLineDTO toDTO(SalesOrderLine line) {
        if (line == null) return null;

        return SalesOrderLineDTO.builder()
                .id(line.getId())
                .salesOrderId(line.getSalesOrder() != null ? line.getSalesOrder().getId() : null)
                .productId(line.getProduct() != null ? line.getProduct().getId() : null)
                .productName(line.getProduct() != null ? line.getProduct().getName() : null)
                .productSku(line.getProduct() != null ? line.getProduct().getCode() : null)
                .quantity(line.getQuantity())
                .unitPrice(line.getUnitPrice())
                .totalPrice(line.getTotalPrice())
                .backordered(line.getBackordered())
                .build();
    }

    public SalesOrderLine toEntity(SalesOrderLineCreateDTO dto) {
        if (dto == null) return null;

        return SalesOrderLine.builder()
                .quantity(dto.getQuantity())
                .unitPrice(dto.getUnitPrice())
                .backordered(dto.getBackordered())
                .build();
    }

    public void updateEntityFromDTO(SalesOrderLineUpdateDTO dto, SalesOrderLine line) {
        if (dto == null || line == null) return;

        if (dto.getQuantity() != null) {
            line.setQuantity(dto.getQuantity());
        }
        if (dto.getUnitPrice() != null) {
            line.setUnitPrice(dto.getUnitPrice());
        }
        if (dto.getBackordered() != null) {
            line.setBackordered(dto.getBackordered());
        }
    }
}