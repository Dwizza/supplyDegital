package org.example.digitallogisticssupplychainplatform.controller;

import jakarta.validation.Valid;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.SupplierDTO;
import org.example.digitallogisticssupplychainplatform.service.SupplierService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Builder
@RequiredArgsConstructor
@RestController
@RequestMapping("api/suppliers")
public class SupplierController {
    private final SupplierService service;

    @PostMapping
    public ResponseEntity<SupplierDTO> createSupplier(@RequestBody @Valid SupplierDTO supplierDTO) {
        SupplierDTO supDto = service.save(supplierDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(supDto);
    }

    @GetMapping
    public ResponseEntity<?> getAllSuppliers() {
        List<SupplierDTO> response = service.findAll();
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> findBySupplierId(@PathVariable Long id) {
        try {
            SupplierDTO response = service.findById(id);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorHandling = new HashMap<>();
            errorHandling.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorHandling);
        }

    }

    @GetMapping("/name/{name}")
    public ResponseEntity<?> findBySupplierName(@PathVariable String name) {
        try {
            Optional<SupplierDTO> response = service.findByName(name);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorHandling = new HashMap<>();
            errorHandling.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorHandling);
        }

    }

    @DeleteMapping("{id}")
    public ResponseEntity<?>removeSupplier(@PathVariable Long id){
           service.deleteById(id);
           Map<String,String>succes=new HashMap<>();
           succes.put("message","supplier deleted succesefly");
           return ResponseEntity.ok(succes);
    }

    @PutMapping("{id}")
    public ResponseEntity<?>updateSupplier(@PathVariable Long id,@RequestBody @Valid SupplierDTO suppdto){
        try{
            SupplierDTO supplierDTOUpdated=service.updateSupplier(id,suppdto);
            return ResponseEntity.ok(supplierDTOUpdated);
        }catch (Exception e){
            Map<String,String>response=new HashMap<>();
            response.put("error",e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

}
