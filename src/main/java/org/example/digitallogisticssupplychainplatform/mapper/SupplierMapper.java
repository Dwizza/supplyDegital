package org.example.digitallogisticssupplychainplatform.mapper;


import jakarta.persistence.*;
import org.example.digitallogisticssupplychainplatform.dto.SupplierDTO;
import org.example.digitallogisticssupplychainplatform.entity.Supplier;
import org.springframework.stereotype.Component;

@Component
public class SupplierMapper {

    public Supplier toEntity(SupplierDTO supplierDto){
        if(supplierDto==null){
            return null;
        }

        return Supplier.builder().name(supplierDto.getName())
                .contactInfo(supplierDto.getContactInfo()).build();
    }

    public SupplierDTO toDto(Supplier supplier){
        if(supplier==null){
            return null;
        }

        return SupplierDTO.builder().id(supplier.getId()).name(supplier.getName()).
                contactInfo(supplier.getContactInfo()).build();
    }

}
