package org.example.digitallogisticssupplychainplatform.controller;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.service.InventoryBusinessService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/api/inventory/operations")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class InventoryBusinessController {

    private final InventoryBusinessService inventoryBusinessService;

    @GetMapping("/{inventoryId}/available")
    public ResponseEntity<AvailabilityResponse> getAvailableQuantity(@PathVariable Long inventoryId) {
        Integer available = inventoryBusinessService.calculateAvailableQty(inventoryId);

        AvailabilityResponse response = AvailabilityResponse.builder()
                .inventoryId(inventoryId)
                .availableQuantity(available)
                .build();

        return ResponseEntity.ok(response);
    }


    @PostMapping("/reserve")
    public ResponseEntity<?> reserveStock(
            @Valid @RequestBody ReservationRequest request) {

        try {
            inventoryBusinessService.reserveStock(
                    request.getProductId(),
                    request.getWarehouseId(),
                    request.getQuantity(),
                    request.getReferenceDoc()
            );

            ReservationResponse response = ReservationResponse.builder()
                    .success(true)
                    .message("Stock réservé avec succès")
                    .productId(request.getProductId())
                    .warehouseId(request.getWarehouseId())
                    .quantityReserved(request.getQuantity())
                    .referenceDoc(request.getReferenceDoc())
                    .build();
            return ResponseEntity.ok(response);
        } catch (Exception e) {
           Map<String,String>error=new HashMap<>();
           error.put("error",e.getMessage());
           return ResponseEntity.ok().body(error);
        }
    }


    @PostMapping("/release")
    public ResponseEntity<ReservationResponse> releaseReservation(@Valid @RequestBody ReservationRequest request) {
        inventoryBusinessService.releaseReservation(
                request.getProductId(),
                request.getWarehouseId(),
                request.getQuantity(),
                request.getReferenceDoc()
        );

        ReservationResponse response = ReservationResponse.builder()
                .success(true)
                .message("Réservation libérée avec succès")
                .productId(request.getProductId())
                .warehouseId(request.getWarehouseId())
                .quantityReserved(request.getQuantity())
                .referenceDoc(request.getReferenceDoc())
                .build();

        return ResponseEntity.ok(response);
    }

    @PostMapping("/inbound")
    public ResponseEntity<InventoryMovementDTO> recordInbound(@Valid @RequestBody MovementRequest request) {
        InventoryMovementDTO movement = inventoryBusinessService.recordInbound(
                request.getProductId(),
                request.getWarehouseId(),
                request.getQuantity(),
                request.getReferenceDoc(),
                request.getDescription()
        );

        return new ResponseEntity<>(movement, HttpStatus.CREATED);
    }


    @PostMapping("/outbound")
    public ResponseEntity<InventoryMovementDTO> recordOutbound(@Valid @RequestBody MovementRequest request) {
        InventoryMovementDTO movement = inventoryBusinessService.recordOutbound(
                request.getProductId(),
                request.getWarehouseId(),
                request.getQuantity(),
                request.getReferenceDoc(),
                request.getDescription()
        );

        return new ResponseEntity<>(movement, HttpStatus.CREATED);
    }

    @PostMapping("/adjustment")
    public ResponseEntity<?> recordAdjustment(@Valid @RequestBody AdjustmentRequest request) {
        try {
            InventoryMovementDTO movement = inventoryBusinessService.recordAdjustment(
                    request.getProductId(),
                    request.getWarehouseId(),
                    request.getAdjustmentQuantity(),
                    request.getReferenceDoc(),
                    request.getReason()
            );

            return new ResponseEntity<>(movement, HttpStatus.CREATED);
        }
        catch (Exception e){
            Map<String,String>error=new HashMap<>();
            error.put("error",e.getMessage());
            return ResponseEntity.ok(error);
        }
    }


    @PostMapping("/allocate")
    public ResponseEntity<AllocationResponse> allocateFromMultipleWarehouses(
            @Valid @RequestBody AllocationRequest request) {

        List<InventoryBusinessService.AllocationResult> allocations =
                inventoryBusinessService.allocateFromMultipleWarehouses(
                        request.getProductId(),
                        request.getTotalQuantity(),
                        request.getWarehouseIdsByPriority()
                );

        Integer totalAllocated = allocations.stream()
                .mapToInt(InventoryBusinessService.AllocationResult::getAllocatedQuantity)
                .sum();

        Integer shortage = request.getTotalQuantity() - totalAllocated;

        AllocationResponse response = AllocationResponse.builder()
                .productId(request.getProductId())
                .requestedQuantity(request.getTotalQuantity())
                .totalAllocated(totalAllocated)
                .shortage(shortage)
                .allocations(allocations)
                .fullyAllocated(shortage == 0)
                .build();

        return ResponseEntity.ok(response);
    }

    @GetMapping("/out-of-stock")
    public ResponseEntity<StockStatusResponse> checkOutOfStock(
            @RequestParam Long productId,
            @RequestParam Long warehouseId) {

        boolean outOfStock = inventoryBusinessService.isOutOfStock(productId, warehouseId);

        StockStatusResponse response = StockStatusResponse.builder()
                .productId(productId)
                .warehouseId(warehouseId)
                .outOfStock(outOfStock)
                .message(outOfStock ? "Produit en rupture de stock" : "Stock disponible")
                .build();

        return ResponseEntity.ok(response);
    }


    @Data
    @Builder
    @AllArgsConstructor
    public static class ReservationRequest {
        @NotNull(message = "L'ID du produit est obligatoire")
        private Long productId;

        @NotNull(message = "L'ID de l'entrepôt est obligatoire")
        private Long warehouseId;

        @NotNull(message = "La quantité est obligatoire")
        @Min(value = 1, message = "La quantité doit être au moins 1")
        private Integer quantity;

        @NotBlank(message = "Le document de référence est obligatoire")
        private String referenceDoc;
    }

    @Data
    @Builder
    public static class ReservationResponse {
        private Boolean success;
        private String message;
        private Long productId;
        private Long warehouseId;
        private Integer quantityReserved;
        private String referenceDoc;
    }

    @Data
    @Builder
    @AllArgsConstructor
    public static class MovementRequest {
        @NotNull(message = "L'ID du produit est obligatoire")
        private Long productId;

        @NotNull(message = "L'ID de l'entrepôt est obligatoire")
        private Long warehouseId;

        @NotNull(message = "La quantité est obligatoire")
        @Min(value = 1, message = "La quantité doit être au moins 1")
        private Integer quantity;

        private String referenceDoc;
        private String description;
    }

    @Data
    @Builder
    @AllArgsConstructor
    public static class AdjustmentRequest {
        @NotNull(message = "L'ID du produit est obligatoire")
        private Long productId;

        @NotNull(message = "L'ID de l'entrepôt est obligatoire")
        private Long warehouseId;

        @NotNull(message = "La quantité d'ajustement est obligatoire")
        private Integer adjustmentQuantity;

        private String referenceDoc;
        private String reason;
    }

    @Data
    @Builder
    @AllArgsConstructor
    public static class AllocationRequest {
        @NotNull(message = "L'ID du produit est obligatoire")
        private Long productId;

        @NotNull(message = "La quantité totale est obligatoire")
        @Min(value = 1, message = "La quantité doit être au moins 1")
        private Integer totalQuantity;

        @NotNull(message = "La liste des entrepôts est obligatoire")
        private List<Long> warehouseIdsByPriority;
    }

    @Data
    @Builder
    public static class AllocationResponse {
        private Long productId;
        private Integer requestedQuantity;
        private Integer totalAllocated;
        private Integer shortage;
        private Boolean fullyAllocated;
        private List<InventoryBusinessService.AllocationResult> allocations;
    }

    @Data
    @Builder
    public static class AvailabilityResponse {
        private Long inventoryId;
        private Integer availableQuantity;
    }

    @Data
    @Builder
    public static class StockStatusResponse {
        private Long productId;
        private Long warehouseId;
        private Boolean outOfStock;
        private String message;
    }
}