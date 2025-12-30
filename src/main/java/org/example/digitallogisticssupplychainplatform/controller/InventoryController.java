package org.example.digitallogisticssupplychainplatform.controller;



import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.InventoryDTO;
import org.example.digitallogisticssupplychainplatform.service.InventoryService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/inventories")
@CrossOrigin(origins = "*")
@Builder
@RequiredArgsConstructor
public class InventoryController {

    private final InventoryService inventoryService;


    @GetMapping
    public ResponseEntity<List<InventoryDTO>> getAllInventories() {

            List<InventoryDTO> inventories = inventoryService.findAll();
            return ResponseEntity.ok(inventories);
    }

    @GetMapping("/{id}")
    public ResponseEntity<InventoryDTO> getInventoryById(@PathVariable Long id) {
        return inventoryService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<?> createInventory(@Valid @RequestBody InventoryDTO inventoryDTO) {
        try {
            InventoryDTO saved = inventoryService.save(inventoryDTO);
            return new ResponseEntity<>(saved, HttpStatus.CREATED);
        } catch (RuntimeException e) {
            System.out.println(e.getMessage());
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<InventoryDTO> updateInventory(
            @PathVariable Long id,
            @Valid @RequestBody InventoryDTO inventoryDTO) {
        try {
            InventoryDTO updated = inventoryService.update(id, inventoryDTO);
            return ResponseEntity.ok(updated);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @PatchMapping("/{id}/quantities")
    public ResponseEntity<InventoryDTO> updateInventoryQuantities(
            @PathVariable Long id,
            @RequestParam Integer qtyOnHand,
            @RequestParam Integer qtyReserved) {
        try {
            InventoryDTO updated = inventoryService.updateQuantities(id, qtyOnHand, qtyReserved);
            return ResponseEntity.ok(updated);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteInventory(@PathVariable Long id) {
        try {
            inventoryService.delete(id);
            return ResponseEntity.noContent().build();
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }
}