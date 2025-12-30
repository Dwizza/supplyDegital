package org.example.digitallogisticssupplychainplatform.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.exception.BusinessException;
import org.example.digitallogisticssupplychainplatform.exception.ResourceNotFoundException;
import org.example.digitallogisticssupplychainplatform.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class PurchaseOrderBusinessService {

    private final PurchaseOrderRepository purchaseOrderRepository;
    private final PurchaseOrderLineRepository purchaseOrderLineRepository;
    private final InventoryBusinessService inventoryBusinessService;
    private final InventoryRepository inventoryRepository;
    private final ProductRepository productRepository;
    private final WareHouseRepository warehouseRepository;

    public ReceiptResult receiveFullOrder(Long purchaseOrderId, Long warehouseId) {
        PurchaseOrder purchaseOrder = getPurchaseOrderOrThrow(purchaseOrderId);
        validateWarehouse(warehouseId);

        if (purchaseOrder.getStatus() == PurchaseOrderStatus.CANCELLED) {
            throw new BusinessException("Impossible de recevoir un PO annulé");
        }

        if (purchaseOrder.getStatus() == PurchaseOrderStatus.DELIVERED) {
            throw new BusinessException("Ce bon de commande a déjà été entièrement reçu");
        }

        List<String> inboundMovements = new ArrayList<>();

        for (PurchaseOrderLine line : purchaseOrder.getOrderLines()) {
            inventoryBusinessService.recordInbound(
                    line.getProduct().getId(),
                    warehouseId,
                    line.getQuantity(),
                    "PO-" + purchaseOrderId,
                    "Réception bon de commande fournisseur - Produit: " + line.getProduct().getName()
            );

            inboundMovements.add("✓ " + line.getProduct().getName() +
                    ": " + line.getQuantity() + " unités reçues");

            log.info("Produit {} - {} unités ajoutées au stock via PO {}",
                    line.getProduct().getCode(), line.getQuantity(), purchaseOrderId);
        }

        purchaseOrder.setStatus(PurchaseOrderStatus.DELIVERED);
        purchaseOrderRepository.save(purchaseOrder);

        log.info("Bon de commande {} complètement reçu - {} ligne(s) traitée(s)",
                purchaseOrderId, inboundMovements.size());

        return ReceiptResult.builder()
                .purchaseOrderId(purchaseOrderId)
                .status(PurchaseOrderStatus.DELIVERED.name())
                .totalLinesProcessed(inboundMovements.size())
                .inboundMovements(inboundMovements)
                .fullyReceived(true)
                .message("Bon de commande entièrement reçu")
                .receivedAt(LocalDateTime.now())
                .build();
    }



    public ApprovalResult approvePurchaseOrder(Long purchaseOrderId) {
        PurchaseOrder purchaseOrder = getPurchaseOrderOrThrow(purchaseOrderId);

        if (purchaseOrder.getStatus() == PurchaseOrderStatus.CONFIRMED) {
            throw new BusinessException("Ce bon de commande est déjà approuvé");
        }

        if (purchaseOrder.getStatus() == PurchaseOrderStatus.CANCELLED) {
            throw new BusinessException("Impossible d'approuver un PO annulé");
        }

        if (purchaseOrder.getOrderLines().isEmpty()) {
            throw new BusinessException("Impossible d'approuver un PO sans lignes");
        }

        purchaseOrder.setStatus(PurchaseOrderStatus.CONFIRMED);
        purchaseOrderRepository.save(purchaseOrder);

        log.info("Bon de commande {} approuvé", purchaseOrderId);

        return ApprovalResult.builder()
                .purchaseOrderId(purchaseOrderId)
                .status(PurchaseOrderStatus.CONFIRMED.name())
                .message("Bon de commande approuvé et prêt pour réception")
                .approvedAt(LocalDateTime.now())
                .build();
    }


    public CancellationResult cancelPurchaseOrder(Long purchaseOrderId, String reason) {
        PurchaseOrder purchaseOrder = getPurchaseOrderOrThrow(purchaseOrderId);

        if (purchaseOrder.getStatus() == PurchaseOrderStatus.DELIVERED) {
            throw new BusinessException(
                    "Impossible d'annuler un PO complètement reçu. Utilisez une note de retour.");
        }

        if (purchaseOrder.getStatus() == PurchaseOrderStatus.CANCELLED) {
            throw new BusinessException("Ce bon de commande est déjà annulé");
        }

        purchaseOrder.setStatus(PurchaseOrderStatus.CANCELLED);
        purchaseOrderRepository.save(purchaseOrder);

        log.info("Bon de commande {} annulé - Raison: {}", purchaseOrderId, reason);

        return CancellationResult.builder()
                .purchaseOrderId(purchaseOrderId)
                .status(PurchaseOrderStatus.CANCELLED.name())
                .reason(reason)
                .message("✓ Bon de commande annulé")
                .cancelledAt(LocalDateTime.now())
                .build();
    }


    public ReceptionStatus checkReceptionStatus(Long purchaseOrderId) {
        PurchaseOrder purchaseOrder = getPurchaseOrderOrThrow(purchaseOrderId);

        List<LineReceptionStatus> lineStatuses = new ArrayList<>();
        Integer totalOrdered = 0;
        Integer totalReceived = 0;
        Integer totalPending = 0;

        for (PurchaseOrderLine line : purchaseOrder.getOrderLines()) {
            Integer receivedQty = 0;
            Integer pending = line.getQuantity() - receivedQty;
            Boolean complete = pending <= 0;

            lineStatuses.add(LineReceptionStatus.builder()
                    .lineId(line.getId())
                    .productName(line.getProduct().getName())
                    .productCode(line.getProduct().getCode())
                    .orderedQty(line.getQuantity())
                    .receivedQty(receivedQty)
                    .pendingQty(Math.max(0, pending))
                    .complete(complete)
                    .build());

            totalOrdered += line.getQuantity();
            totalReceived += receivedQty;
            totalPending += Math.max(0, pending);
        }

        Boolean fullyReceived = totalPending == 0;

        return ReceptionStatus.builder()
                .purchaseOrderId(purchaseOrderId)
                .status(purchaseOrder.getStatus().name())
                .totalOrdered(totalOrdered)
                .totalReceived(totalReceived)
                .totalPending(totalPending)
                .percentageReceived((totalOrdered > 0) ?
                        (totalReceived * 100 / totalOrdered) : 0)
                .fullyReceived(fullyReceived)
                .lineStatuses(lineStatuses)
                .build();
    }


    public StockAvailabilityForPO getStockAvailability(Long purchaseOrderId, Long warehouseId) {
        PurchaseOrder purchaseOrder = getPurchaseOrderOrThrow(purchaseOrderId);
        validateWarehouse(warehouseId);

        List<ProductStockInfo> productStocks = new ArrayList<>();

        for (PurchaseOrderLine line : purchaseOrder.getOrderLines()) {
            Inventory inventory = inventoryRepository.findByProductIdAndWarehouseId(
                    line.getProduct().getId(), warehouseId);

            Integer qtyOnHand = inventory != null ? inventory.getQtyOnHand() : 0;
            Integer qtyReserved = inventory != null ? inventory.getQtyReserved() : 0;
            Integer available = qtyOnHand - qtyReserved;

            productStocks.add(ProductStockInfo.builder()
                    .productId(line.getProduct().getId())
                    .productCode(line.getProduct().getCode())
                    .productName(line.getProduct().getName())
                    .poLineQuantity(line.getQuantity())
                    .currentQtyOnHand(qtyOnHand)
                    .currentQtyReserved(qtyReserved)
                    .currentAvailable(available)
                    .willBeSufficient(available >= line.getQuantity())
                    .build());
        }

        return StockAvailabilityForPO.builder()
                .purchaseOrderId(purchaseOrderId)
                .warehouseId(warehouseId)
                .productStocks(productStocks)
                .build();
    }


    private PurchaseOrder getPurchaseOrderOrThrow(Long purchaseOrderId) {
        return purchaseOrderRepository.findById(purchaseOrderId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Bon de commande introuvable: " + purchaseOrderId));
    }

    private void validateWarehouse(Long warehouseId) {
        if (!warehouseRepository.existsById(warehouseId)) {
            throw new BusinessException("Entrepôt introuvable: " + warehouseId);
        }
    }



    @Data
    @Builder
    public static class ReceiptResult {
        private Long purchaseOrderId;
        private String status;
        private Integer totalLinesProcessed;
        private List<String> inboundMovements;
        private Boolean fullyReceived;
        private String message;
        private LocalDateTime receivedAt;
    }

    @Data
    @Builder
    public static class PartialLineReceipt {
        private Long lineId;
        private Integer quantityReceived;
        private String receptionNotes;
    }

    @Data
    @Builder
    public static class PartialReceiptResult {
        private Long purchaseOrderId;
        private String status;
        private Integer totalQuantityReceived;
        private List<String> successMessages;
        private List<String> errors;
        private Boolean fullyReceived;
        private String message;
        private LocalDateTime receivedAt;
    }

    @Data
    @Builder
    public static class ApprovalResult {
        private Long purchaseOrderId;
        private String status;
        private String message;
        private LocalDateTime approvedAt;
    }

    @Data
    @Builder
    public static class CancellationResult {
        private Long purchaseOrderId;
        private String status;
        private String reason;
        private String message;
        private LocalDateTime cancelledAt;
    }

    @Data
    @Builder
    public static class ReceptionStatus {
        private Long purchaseOrderId;
        private String status;
        private Integer totalOrdered;
        private Integer totalReceived;
        private Integer totalPending;
        private Integer percentageReceived;
        private Boolean fullyReceived;
        private List<LineReceptionStatus> lineStatuses;
    }

    @Data
    @Builder
    public static class LineReceptionStatus {
        private Long lineId;
        private String productName;
        private String productCode;
        private Integer orderedQty;
        private Integer receivedQty;
        private Integer pendingQty;
        private Boolean complete;
    }

    @Data
    @Builder
    public static class StockAvailabilityForPO {
        private Long purchaseOrderId;
        private Long warehouseId;
        private List<ProductStockInfo> productStocks;
    }

    @Data
    @Builder
    public static class ProductStockInfo {
        private Long productId;
        private String productCode;
        private String productName;
        private Integer poLineQuantity;
        private Integer currentQtyOnHand;
        private Integer currentQtyReserved;
        private Integer currentAvailable;
        private Boolean willBeSufficient;
    }
}