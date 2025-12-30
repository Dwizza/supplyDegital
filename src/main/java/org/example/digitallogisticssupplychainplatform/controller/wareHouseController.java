package org.example.digitallogisticssupplychainplatform.controller;


import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.WareHouseDto;
import org.example.digitallogisticssupplychainplatform.service.WareHouseService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("api/wareHouse")
@RequiredArgsConstructor
public class wareHouseController {
private final WareHouseService wareHouseService;
    @PostMapping
    public ResponseEntity<?> createWareHouse(@Valid @RequestBody WareHouseDto wareHouseDto){
     WareHouseDto warehouseCreated=wareHouseService.save(wareHouseDto);
     return ResponseEntity.status(HttpStatus.CREATED).body(warehouseCreated);
    }
    @GetMapping
    public ResponseEntity<?> getAllWarehouses(){
        List <WareHouseDto> wareHouses=wareHouseService.findAll();
        return ResponseEntity.ok(wareHouses);
    }
    @GetMapping("/{id}")
    public ResponseEntity<?> getWareHouse(@PathVariable Long id){
        WareHouseDto warehouse=wareHouseService.findById(id);
        return ResponseEntity.ok().body(warehouse);
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteWareHouse(@PathVariable Long id){
        wareHouseService.deleteById(id);
        Map<String,String>response=new HashMap<>();
        response.put("succes","wareHouse Deleted Succesufly");
        return ResponseEntity.ok(response);
    }
    @PutMapping("/{id}")
    public ResponseEntity<?>updateWareahouse(@PathVariable Long id,@RequestBody WareHouseDto wareHouseDto){
        WareHouseDto wareHouseDtoUpdated=wareHouseService.updateWareHouse(id,wareHouseDto);
        return ResponseEntity.ok(wareHouseDtoUpdated);
    }
}
