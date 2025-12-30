package org.example.digitallogisticssupplychainplatform.mapper;

import org.example.digitallogisticssupplychainplatform.dto.WareHouseDto;
import org.example.digitallogisticssupplychainplatform.entity.WareHouse;
import org.springframework.stereotype.Component;

@Component
public class WareHouseMapper {

    public WareHouse toEntity(WareHouseDto wareHouseDto){
        if(wareHouseDto==null){
            return null;
        }
        return WareHouse.builder().name(wareHouseDto.getName())
                .code(wareHouseDto.getCode())
                .build();
    }
    public WareHouseDto toResponseDto(WareHouse wareHouse){
        if(wareHouse==null){
            return null;
        }
        return WareHouseDto.builder().id(wareHouse.getId()).
                name(wareHouse.getName()).code(wareHouse.getCode())
                .active(wareHouse.isActive()).
                build();
    }
}
