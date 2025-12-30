package org.example.digitallogisticssupplychainplatform.service;

import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.SupplierDTO;
import org.example.digitallogisticssupplychainplatform.entity.Supplier;
import org.example.digitallogisticssupplychainplatform.mapper.SupplierMapper;
import org.example.digitallogisticssupplychainplatform.repository.SupplierRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Builder
@RequiredArgsConstructor
public class SupplierService {
    private final SupplierRepository repo;
    private final SupplierMapper mapper;

    public SupplierDTO save(SupplierDTO supplierDto){
        Supplier supp=mapper.toEntity(supplierDto);
        Supplier savded=repo.save(supp);
        SupplierDTO result=mapper.toDto(savded);
        return result;
    }

    public List<SupplierDTO> findAll(){
        return repo.findAll().stream().map(mapper::toDto).toList();
    }

    public SupplierDTO findById(Long id){
        return repo.findById(id).map(mapper::toDto).orElseThrow(()->new RuntimeException("Suplier avec id specifie n'existe pas"));
    }
    public Optional<SupplierDTO> findByName(String name){
        return repo.findByName(name).map(mapper::toDto);
    }
    public void deleteById(Long id){
        repo.deleteById(id);
    }

    public SupplierDTO updateSupplier(Long id,SupplierDTO supplier){
        Supplier supp=repo.findById(id).orElseThrow(()->new RuntimeException("user avec id not found"));

        supp.setName(supplier.getName());
        supp.setContactInfo(supplier.getContactInfo());

        Supplier supplierUpdated=repo.save(supp);
        return mapper.toDto(supplierUpdated);
    }

}
