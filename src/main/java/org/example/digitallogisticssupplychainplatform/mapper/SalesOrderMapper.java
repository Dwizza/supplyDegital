package org.example.digitallogisticssupplychainplatform.mapper;
import org.example.digitallogisticssupplychainplatform.dto.*;
import org.example.digitallogisticssupplychainplatform.entity.SalesOrder;
import org.example.digitallogisticssupplychainplatform.entity.User;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.stream.Collectors;

@Component
public class SalesOrderMapper {

    private final SalesOrderLineMapper lineMapper;

    public SalesOrderMapper(SalesOrderLineMapper lineMapper) {
        this.lineMapper = lineMapper;
    }

    public SalesOrderDTO toDTO(SalesOrder order) {
        if (order == null) return null;

        var dto = SalesOrderDTO.builder()
                .id(order.getId())
                .clientId(order.getClient() != null ? order.getClient().getId() : null)
                .clientName(order.getClient() != null ? order.getClient().getUsername() : null)
                .createdAt(order.getCreatedAt())
                .reservedAt(order.getReservedAt())
                .shippedAt(order.getShippedAt())
                .deliveredAt(order.getDeliveredAt())
                .build();

        if (order.getOrderLines() != null) {
            dto.setOrderLines(order.getOrderLines().stream()
                    .map(lineMapper::toDTO)
                    .collect(Collectors.toList()));

            dto.setTotalAmount(order.getOrderLines().stream()
                    .map(line -> line.getUnitPrice().multiply(BigDecimal.valueOf(line.getQuantity())))
                    .reduce(BigDecimal.ZERO, BigDecimal::add));
        }

        return dto;
    }

    public SalesOrder toEntity(SalesOrderCreateDTO dto, User client) {
        if (dto == null) return null;

        var order = SalesOrder.builder()
                .client(client)
                .build();

        if (dto.getOrderLines() != null) {
            dto.getOrderLines().forEach(lineDTO -> {
                var line = lineMapper.toEntity(lineDTO);
                order.addOrderLine(line);
            });
        }

        return order;
    }

    public void updateEntityFromDTO(SalesOrderUpdateDTO dto, SalesOrder order) {
        if (dto == null || order == null) return;

        if (dto.getReservedAt() != null) {
            order.setReservedAt(dto.getReservedAt());
        }
        if (dto.getShippedAt() != null) {
            order.setShippedAt(dto.getShippedAt());
        }
        if (dto.getDeliveredAt() != null) {
            order.setDeliveredAt(dto.getDeliveredAt());
        }
    }
}
