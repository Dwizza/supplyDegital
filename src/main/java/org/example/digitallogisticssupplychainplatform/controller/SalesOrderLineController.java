package org.example.digitallogisticssupplychainplatform.controller;

import jakarta.validation.Valid;
import org.example.digitallogisticssupplychainplatform.dto.*;
import org.example.digitallogisticssupplychainplatform.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;
@RestController
@RequestMapping("/api/sales-order-lines")
@RequiredArgsConstructor
public class SalesOrderLineController {

    private final SalesOrderLineService lineService;

    @GetMapping("/order/{orderId}")
    public ResponseEntity<List<SalesOrderLineDTO>> getLinesByOrder(@PathVariable Long orderId) {
        List<SalesOrderLineDTO> lines = lineService.findByOrderId(orderId);
        return ResponseEntity.ok(lines);
    }

    @GetMapping("/{id}")
    public ResponseEntity<SalesOrderLineDTO> getLineById(@PathVariable Long id) {
        SalesOrderLineDTO line = lineService.findById(id);
        return ResponseEntity.ok(line);
    }

    @PostMapping("/order/{orderId}")
    public ResponseEntity<SalesOrderLineDTO> addLineToOrder(
            @PathVariable Long orderId,
            @Valid @RequestBody SalesOrderLineCreateDTO dto) {
        SalesOrderLineDTO created = lineService.addLineToOrder(orderId, dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}")
    public ResponseEntity<SalesOrderLineDTO> updateLine(
            @PathVariable Long id,
            @Valid @RequestBody SalesOrderLineUpdateDTO dto) {
        SalesOrderLineDTO updated = lineService.updateLine(id, dto);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteLine(@PathVariable Long id) {
        lineService.deleteLine(id);
        return ResponseEntity.noContent().build();
    }
}


