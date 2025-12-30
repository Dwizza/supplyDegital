package org.example.digitallogisticssupplychainplatform.repository;

import org.example.digitallogisticssupplychainplatform.dto.SupplierDTO;
import org.example.digitallogisticssupplychainplatform.entity.Supplier;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface SupplierRepository extends JpaRepository<Supplier,Long> {

    Optional<Supplier> findByName(String name);
}
