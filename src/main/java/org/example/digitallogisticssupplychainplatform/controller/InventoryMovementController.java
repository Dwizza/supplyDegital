
package org.example.digitallogisticssupplychainplatform.controller;

import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.service.InventoryMovementService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/inventory-movements")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class InventoryMovementController {

    private final InventoryMovementService movementService;

    @GetMapping
    public ResponseEntity<List<InventoryMovementDTO>> getAllMovements() {
        List<InventoryMovementDTO> movements = movementService.findAll();
        return ResponseEntity.ok(movements);
    }

    @GetMapping("/{id}")
    public ResponseEntity<InventoryMovementDTO> getMovementById(@PathVariable Long id) {
        try {
            InventoryMovementDTO movement = movementService.findById(id);
            return ResponseEntity.ok(movement);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/inventory/{inventoryId}")
    public ResponseEntity<List<InventoryMovementDTO>> getMovementsByInventory(@PathVariable Long inventoryId) {
        List<InventoryMovementDTO> movements = movementService.findByInventoryId(inventoryId);
        return ResponseEntity.ok(movements);
    }

    @GetMapping("/product/{productId}")
    public ResponseEntity<List<InventoryMovementDTO>> getMovementsByProduct(@PathVariable Long productId) {
        List<InventoryMovementDTO> movements = movementService.findByProductId(productId);
        return ResponseEntity.ok(movements);
    }

    @GetMapping("/warehouse/{warehouseId}")
    public ResponseEntity<List<InventoryMovementDTO>> getMovementsByWarehouse(@PathVariable Long warehouseId) {
        List<InventoryMovementDTO> movements = movementService.findByWarehouseId(warehouseId);
        return ResponseEntity.ok(movements);
    }

    @GetMapping("/type/{type}")
    public ResponseEntity<List<InventoryMovementDTO>> getMovementsByType(@PathVariable String type) {
        List<InventoryMovementDTO> movements = movementService.findByType(type);
        return ResponseEntity.ok(movements);
    }

    @GetMapping("/date-range")
    public ResponseEntity<List<InventoryMovementDTO>> getMovementsByDateRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {
        List<InventoryMovementDTO> movements = movementService.findByDateRange(startDate, endDate);
        return ResponseEntity.ok(movements);
    }

    @PostMapping
    public ResponseEntity<?> createMovement(@RequestBody InventoryMovementDTO movementDTO) {
        try {
            InventoryMovementDTO saved = movementService.createMovement(movementDTO);
            return new ResponseEntity<>(saved, HttpStatus.CREATED);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteMovement(@PathVariable Long id) {
        try {
            movementService.deleteMovement(id);
            return ResponseEntity.noContent().build();
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }
}