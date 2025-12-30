package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.ProductDTO;
import java.util.List;
import java.util.Optional;

public interface ProductService {
    List<ProductDTO> findAll();
    List<ProductDTO> findAllActive();
    Optional<ProductDTO> findById(Long id);
    Optional<ProductDTO> findByCode(String code);
    List<ProductDTO> findByCategory(String category);
    ProductDTO save(ProductDTO productDTO);
    ProductDTO update(Long id, ProductDTO productDTO);
    void delete(Long id);
    ProductDTO deactivate(Long id);
    ProductDTO activate(Long id);
    boolean existsByCode(String code);
}