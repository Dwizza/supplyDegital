package org.example.digitallogisticssupplychainplatform.controller;


import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.CarrierDTO;
import org.example.digitallogisticssupplychainplatform.service.CarrierService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/carriers")
@Builder
@RequiredArgsConstructor
public class CarrierController {
    private final CarrierService service;
    @PostMapping
    public ResponseEntity<?> createCarrier(@RequestBody CarrierDTO carrierDto){
        try {
            CarrierDTO carrierSaved=service.save(carrierDto);
            return ResponseEntity.ok(carrierSaved);
        }catch (Exception e){
            Map<String,String> errors=new HashMap<>();
            errors.put("error",e.getMessage());
            return ResponseEntity.badRequest().body(errors);
        }

    }

    @GetMapping
    public ResponseEntity<?>getAllCarriers(){
        try {
            List<CarrierDTO> carriers = service.findAll();
            return ResponseEntity.ok().body(carriers);
        }
         catch(Exception e){
            Map<String,String> errors=new HashMap<>();
            errors.put("error",e.getMessage());
            return ResponseEntity.badRequest().body(errors);
        }
    }

    @GetMapping("{id}")
    public ResponseEntity<?> getCarrier(@PathVariable Long id){
        CarrierDTO carrier=service.findById(id);
        return ResponseEntity.ok().body(carrier);
    }

    @PutMapping("{id}")
    public ResponseEntity<?> updateCarrier(@PathVariable Long id, @RequestBody CarrierDTO carrierDto) {
        try {
            CarrierDTO updatedCarrier = service.update(id, carrierDto);
            return ResponseEntity.ok(updatedCarrier);
        } catch (Exception e) {
            Map<String, String> errors = new HashMap<>();
            errors.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errors);
        }
    }

    @PatchMapping("{id}/status")
    public ResponseEntity<?> updateCarrierStatus(@PathVariable Long id, @RequestBody Map<String, String> request) {
        try {
            String status = request.get("status");
            CarrierDTO updatedCarrier = service.updateStatus(id, status);
            return ResponseEntity.ok(updatedCarrier);
        } catch (Exception e) {
            Map<String, String> errors = new HashMap<>();
            errors.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errors);
        }
    }

    @DeleteMapping("{id}")
    public ResponseEntity<?> deleteCarrier(@PathVariable Long id) {
        try {
            service.delete(id);
            Map<String, String> response = new HashMap<>();
            response.put("message", "Carrier supprimé avec succès");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errors = new HashMap<>();
            errors.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errors);
        }
    }

}
