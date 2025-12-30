package org.example.digitallogisticssupplychainplatform.service;

import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.WareHouseDto;
import org.example.digitallogisticssupplychainplatform.entity.WareHouse;
import org.example.digitallogisticssupplychainplatform.mapper.WareHouseMapper;
import org.example.digitallogisticssupplychainplatform.repository.WareHouseRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class WareHouseService {
private final WareHouseRepository repo;
private final WareHouseMapper mapper;

public WareHouseDto save(WareHouseDto wareHousedto){
WareHouse wareHouse=mapper.toEntity(wareHousedto);
WareHouse wareHouseCreated=repo.save(wareHouse);
return mapper.toResponseDto(wareHouseCreated);
}
public List<WareHouseDto> findAll(){
    return repo.findAll().stream().map(mapper::toResponseDto).toList();
}
public WareHouseDto findById(Long id){
    return repo.findById(id).map(mapper::toResponseDto).orElseThrow(()->new RuntimeException("wareHouse non trouve"));
}
public void deleteById(Long id){
    repo.deleteById(id);
}
public WareHouseDto updateWareHouse(Long id,WareHouseDto wareHouseDto){
    WareHouse wareHouse=repo.findById(id).orElseThrow(()->new RuntimeException("warehouse not found"));

    wareHouse.setName(wareHouseDto.getName());
    wareHouse.setCode(wareHouseDto.getCode());
    wareHouse.setActive(wareHouse.isActive());

    WareHouse wareHouseUpdated=repo.save(wareHouse);
    return mapper.toResponseDto(wareHouseUpdated);
}
}

