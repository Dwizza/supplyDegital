package org.example.digitallogisticssupplychainplatform.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.exception.BusinessException;
import org.example.digitallogisticssupplychainplatform.exception.ResourceNotFoundException;
import org.example.digitallogisticssupplychainplatform.exception.StockUnavailableException;
import org.example.digitallogisticssupplychainplatform.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;


@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class SalesOrderBusinessService {

    private final SalesOrderRepository salesOrderRepository;
    private final InventoryBusinessService inventoryBusinessService;
    private final InventoryRepository inventoryRepository;


    public ReservationResult reserveOrder(Long orderId, Long warehouseId) {
        SalesOrder order = salesOrderRepository.findById(orderId)
                .orElseThrow(() -> new ResourceNotFoundException("Commande introuvable: " + orderId));


        if (order.getReservedAt() != null) {
            throw new BusinessException("La commande est déjà réservée");
        }
        if (order.getShippedAt() != null) {
            throw new BusinessException("La commande est déjà expédiée");
        }

        List<String> successMessages = new ArrayList<>();
        List<BackorderInfo> backorders = new ArrayList<>();
        boolean fullyReserved = true;


        for (SalesOrderLine line : order.getOrderLines()) {
            try {
                if (!line.getProduct().isActive()) {
                    throw new BusinessException("Produit " + line.getProduct().getCode() + " inactif");
                }


                inventoryBusinessService.reserveStock(
                        line.getProduct().getId(),
                        warehouseId,
                        line.getQuantity(),
                        "SO-" + orderId
                );

                successMessages.add( line.getProduct().getName() + ": " +
                        line.getQuantity() + " unités réservées");

                Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(
                        line.getProduct().getId(), warehouseId);

                Integer available = inventory != null ?
                        (inventory.getQtyOnHand() - inventory.getQtyReserved()) : 0;

                if (available < line.getQuantity()) {
                    fullyReserved = false;
                    Integer shortage = line.getQuantity() - available;

                    line.setBackordered(true);

                    backorders.add(BackorderInfo.builder()
                            .productCode(line.getProduct().getCode())
                            .productName(line.getProduct().getName())
                            .requestedQty(line.getQuantity())
                            .availableQty(available)
                            .shortageQty(shortage)
                            .build());

                    log.info("⚠ BACKORDER: {} unités manquantes pour {}",
                            shortage, line.getProduct().getName());
                }

            } catch (StockUnavailableException e) {

                fullyReserved = false;

                Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(
                        line.getProduct().getId(), warehouseId);

                Integer available = inventory != null ?
                        (inventory.getQtyOnHand() - inventory.getQtyReserved()) : 0;
                Integer shortage = line.getQuantity() - available;

                backorders.add(BackorderInfo.builder()
                        .productCode(line.getProduct().getCode())
                        .productName(line.getProduct().getName())
                        .requestedQty(line.getQuantity())
                        .availableQty(available)
                        .shortageQty(shortage)
                        .build());
                line.setBackordered(true);

                if (available > 0) {
                    inventoryBusinessService.reserveStock(
                            line.getProduct().getId(),
                            warehouseId,
                            available,
                            "SO-" + orderId + "-PARTIAL"
                    );
                    successMessages.add( line.getProduct().getName() + ": " +
                            available + " unités réservées (partiel)");
                }
            }
        }


        order.setReservedAt(LocalDateTime.now());
        salesOrderRepository.save(order);

        log.info("Commande {} réservée - Complète: {}", orderId, fullyReserved);

        return ReservationResult.builder()
                .orderId(orderId)
                .fullyReserved(fullyReserved)
                .reservedAt(order.getReservedAt())
                .successMessages(successMessages)
                .backorders(backorders)
                .message(fullyReserved ?
                        "Commande entièrement réservée" :
                        "Commande partiellement réservée (" + backorders.size() + " backorder(s))")
                .build();
    }

    public ShipmentResult shipOrder(Long orderId, Long warehouseId) {
        SalesOrder order = salesOrderRepository.findById(orderId)
                .orElseThrow(() -> new ResourceNotFoundException("Commande introuvable: " + orderId));

        if (order.getReservedAt() == null) {
            throw new BusinessException("La commande doit être réservée avant l'expédition");
        }
        if (order.getShippedAt() != null) {
            throw new BusinessException("La commande est déjà expédiée");
        }

        List<String> movements = new ArrayList<>();

        for (SalesOrderLine line : order.getOrderLines()) {
            if (!line.getBackordered()) {
                inventoryBusinessService.recordOutbound(
                        line.getProduct().getId(),
                        warehouseId,
                        line.getQuantity(),
                        "SO-" + orderId,
                        "Expédition commande client"
                );

                movements.add("✓ " + line.getProduct().getName() + ": " +
                        line.getQuantity() + " unités expédiées");
            }
        }

        order.setShippedAt(LocalDateTime.now());
        salesOrderRepository.save(order);

        log.info("Commande {} expédiée - {} mouvement(s)", orderId, movements.size());

        return ShipmentResult.builder()
                .orderId(orderId)
                .shippedAt(order.getShippedAt())
                .movements(movements)
                .message("✓ Commande expédiée avec succès")
                .build();
    }


    public void deliverOrder(Long orderId) {
        SalesOrder order = salesOrderRepository.findById(orderId)
                .orElseThrow(() -> new ResourceNotFoundException("Commande introuvable: " + orderId));

        if (order.getShippedAt() == null) {
            throw new BusinessException("La commande doit être expédiée avant d'être livrée");
        }
        if (order.getDeliveredAt() != null) {
            throw new BusinessException("La commande est déjà livrée");
        }

        order.setDeliveredAt(LocalDateTime.now());
        salesOrderRepository.save(order);

        log.info("Commande {} livrée", orderId);
    }


    public CancellationResult cancelOrder(Long orderId, String reason,Long warehouseId) {
        SalesOrder order = salesOrderRepository.findById(orderId)
                .orElseThrow(() -> new ResourceNotFoundException("Commande introuvable: " + orderId));


        if (order.getShippedAt() != null) {
            throw new BusinessException("Impossible d'annuler une commande expédiée");
        }
        if (order.getDeliveredAt() != null) {
            throw new BusinessException("Impossible d'annuler une commande livrée");
        }

        List<String> releasedReservations = new ArrayList<>();

        if (order.getReservedAt() != null) {
            for (SalesOrderLine line : order.getOrderLines()) {
                if (!line.getBackordered()) {
                    try {
                        Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(
                                line.getProduct().getId(), warehouseId);

                        if (inventory != null) {
                            inventoryBusinessService.releaseReservation(
                                    line.getProduct().getId(),
                                    inventory.getWarehouse().getId(),
                                    line.getQuantity(),
                                    "SO-" + orderId + "-CANCEL"
                            );

                            releasedReservations.add("✓ " + line.getProduct().getName() + ": " +
                                    line.getQuantity() + " unités libérées");
                        }
                    } catch (Exception e) {
                        log.error("Erreur libération pour ligne {}: {}", line.getId(), e.getMessage());
                    }
                }
            }
        }

        salesOrderRepository.delete(order);

        log.info("Commande {} annulée - Raison: {}", orderId, reason);

        return CancellationResult.builder()
                .orderId(orderId)
                .cancelledAt(LocalDateTime.now())
                .reason(reason)
                .releasedReservations(releasedReservations)
                .message("✓ Commande annulée - " + releasedReservations.size() +
                        " réservation(s) libérée(s)")
                .build();
    }

    public AvailabilityCheck checkAvailability(Long orderId, Long warehouseId) {
        SalesOrder order = salesOrderRepository.findById(orderId)
                .orElseThrow(() -> new ResourceNotFoundException("Commande introuvable: " + orderId));

        List<ProductAvailability> products = new ArrayList<>();
        boolean canReserve = true;

        for (SalesOrderLine line : order.getOrderLines()) {
            Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(
                    line.getProduct().getId(), warehouseId);

            Integer available = inventory != null ?
                    (inventory.getQtyOnHand() - inventory.getQtyReserved()) : 0;

            boolean sufficient = available >= line.getQuantity();
            if (!sufficient) {
                canReserve = false;
            }

            products.add(ProductAvailability.builder()
                    .productCode(line.getProduct().getCode())
                    .productName(line.getProduct().getName())
                    .requestedQty(line.getQuantity())
                    .availableQty(available)
                    .sufficient(sufficient)
                    .build());
        }

        return AvailabilityCheck.builder()
                .orderId(orderId)
                .canReserveCompletely(canReserve)
                .products(products)
                .build();
    }



    @Data
    @Builder
    public static class ReservationResult {
        private Long orderId;
        private Boolean fullyReserved;
        private LocalDateTime reservedAt;
        private List<String> successMessages;
        private List<BackorderInfo> backorders;
        private String message;
    }

    @Data
    @Builder
    public static class BackorderInfo {
        private String productCode;
        private String productName;
        private Integer requestedQty;
        private Integer availableQty;
        private Integer shortageQty;
    }

    @Data
    @Builder
    public static class ShipmentResult {
        private Long orderId;
        private LocalDateTime shippedAt;
        private List<String> movements;
        private String message;
    }

    @Data
    @Builder
    public static class CancellationResult {
        private Long orderId;
        private LocalDateTime cancelledAt;
        private String reason;
        private List<String> releasedReservations;
        private String message;
    }

    @Data
    @Builder
    public static class AvailabilityCheck {
        private Long orderId;
        private Boolean canReserveCompletely;
        private List<ProductAvailability> products;
    }

    @Data
    @Builder
    public static class ProductAvailability {
        private String productCode;
        private String productName;
        private Integer requestedQty;
        private Integer availableQty;
        private Boolean sufficient;
    }
}