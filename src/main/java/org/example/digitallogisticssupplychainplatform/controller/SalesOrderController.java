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
@RequestMapping("/api/sales-orders")
@RequiredArgsConstructor
public class SalesOrderController {

    private final SalesOrderService salesOrderService;

    @GetMapping
    public ResponseEntity<List<SalesOrderDTO>> getAllOrders() {
        List<SalesOrderDTO> orders = salesOrderService.findAll();
        return ResponseEntity.ok(orders);
    }

    @GetMapping("/{id}")
    public ResponseEntity<SalesOrderDTO> getOrderById(@PathVariable Long id) {
        SalesOrderDTO order = salesOrderService.findById(id);
        return ResponseEntity.ok(order);
    }

    @GetMapping("/client/{clientId}")
    public ResponseEntity<List<SalesOrderDTO>> getOrdersByClient(@PathVariable Long clientId) {
        List<SalesOrderDTO> orders = salesOrderService.findByClientId(clientId);
        return ResponseEntity.ok(orders);
    }

    @PostMapping
    public ResponseEntity<SalesOrderDTO> createOrder(@Valid @RequestBody SalesOrderCreateDTO dto) {
        SalesOrderDTO created = salesOrderService.create(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}")
    public ResponseEntity<SalesOrderDTO> updateOrder(
            @PathVariable Long id,
            @Valid @RequestBody SalesOrderUpdateDTO dto) {
        SalesOrderDTO updated = salesOrderService.update(id, dto);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteOrder(@PathVariable Long id) {
        salesOrderService.delete(id);
        return ResponseEntity.noContent().build();
    }
}