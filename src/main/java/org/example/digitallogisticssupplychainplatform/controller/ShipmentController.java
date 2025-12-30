package org.example.digitallogisticssupplychainplatform.controller;

import jakarta.validation.Valid;
import org.example.digitallogisticssupplychainplatform.dto.*;
import org.example.digitallogisticssupplychainplatform.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/shipments")
@RequiredArgsConstructor
public class ShipmentController {

    private final ShipmentService shipmentService;

    @GetMapping
    public ResponseEntity<List<ShipmentDTO>> getAllShipments() {
        List<ShipmentDTO> shipments = shipmentService.findAll();
        return ResponseEntity.ok(shipments);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ShipmentDTO> getShipmentById(@PathVariable Long id) {
        ShipmentDTO shipment = shipmentService.findById(id);
        return ResponseEntity.ok(shipment);
    }

    @GetMapping("/tracking/{trackingNumber}")
    public ResponseEntity<ShipmentDTO> getShipmentByTracking(@PathVariable String trackingNumber) {
        ShipmentDTO shipment = shipmentService.findByTrackingNumber(trackingNumber);
        return ResponseEntity.ok(shipment);
    }

    @GetMapping("/carrier/{carrierId}")
    public ResponseEntity<List<ShipmentDTO>> getShipmentsByCarrier(@PathVariable Long carrierId) {
        List<ShipmentDTO> shipments = shipmentService.findByCarrierId(carrierId);
        return ResponseEntity.ok(shipments);
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<List<ShipmentDTO>> getShipmentsByStatus(@PathVariable String status) {
        List<ShipmentDTO> shipments = shipmentService.findByStatus(status);
        return ResponseEntity.ok(shipments);
    }

    @PostMapping
    public ResponseEntity<?> createShipment(@Valid @RequestBody ShipmentCreateDTO dto) {
        try {
            ShipmentDTO created = shipmentService.create(dto);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        }catch (Exception e){
            Map<String,String>error=new HashMap<>();
            error.put("error",e.getMessage());
            return ResponseEntity.ok(error);
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<ShipmentDTO> updateShipment(
            @PathVariable Long id,
            @Valid @RequestBody ShipmentUpdateDTO dto) {
        ShipmentDTO updated = shipmentService.update(id, dto);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteShipment(@PathVariable Long id) {
        shipmentService.delete(id);
        return ResponseEntity.noContent().build();
    }
}

