package org.example.digitallogisticssupplychainplatform.service;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.ProductDTO;
import org.example.digitallogisticssupplychainplatform.entity.Product;
import org.example.digitallogisticssupplychainplatform.entity.ProductStatus;
import org.example.digitallogisticssupplychainplatform.entity.User;
import org.example.digitallogisticssupplychainplatform.mapper.ProductMapper;
import org.example.digitallogisticssupplychainplatform.repository.ProductRepository;
import org.example.digitallogisticssupplychainplatform.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class ProductServiceImpl implements ProductService {

    private final ProductRepository productRepository;
    private final UserRepository userRepository;
    private final ProductMapper productMapper;

    @Override
    @Transactional(readOnly = true)
    public List<ProductDTO> findAll() {
        return productRepository.findAll().stream()
                .map(productMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<ProductDTO> findAllActive() {
        return productRepository.findAllActive().stream()
                .map(productMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<ProductDTO> findById(Long id) {
        return productRepository.findById(id)
                .map(productMapper::toDto);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<ProductDTO> findByCode(String code) {
        return productRepository.findByCode(code)
                .map(productMapper::toDto);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ProductDTO> findByCategory(String category) {
        return productRepository.findByCategory(category).stream()
                .map(productMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    public ProductDTO save(ProductDTO productDTO) {
        if (productRepository.existsByCode(productDTO.getCode())) {
            throw new RuntimeException("Un produit avec le code " + productDTO.getCode() + " existe déjà");
        }

        Product product = productMapper.toEntity(productDTO);

        Product saved = productRepository.save(product);
        return productMapper.toDto(saved);
    }

    @Override
    public ProductDTO update(Long id, ProductDTO productDTO) {
        return productRepository.findById(id)
                .map(existingProduct -> {
                    if (!existingProduct.getCode().equals(productDTO.getCode()) &&
                            productRepository.existsByCode(productDTO.getCode())) {
                        throw new RuntimeException("Un produit avec le code " + productDTO.getCode() + " existe déjà");
                    }

                    existingProduct.setCode(productDTO.getCode());
                    existingProduct.setName(productDTO.getName());
                    existingProduct.setDescription(productDTO.getDescription());
                    existingProduct.setMainStyle(productDTO.getMainStyle());
                    existingProduct.setOptionLevel(productDTO.getOptionLevel());
                    existingProduct.setCategory(productDTO.getCategory());
                    existingProduct.setConfiguration(productDTO.getConfiguration());
                    existingProduct.setBase(productDTO.getBase());
                    existingProduct.setActualEmail(productDTO.getActualEmail());
                    existingProduct.setActive(productDTO.getActive());
                    existingProduct.setIndex(productDTO.getIndex());
                    existingProduct.setProfile(productDTO.getProfile());
                    existingProduct.setLastModifiedDate(LocalDateTime.now());

                    Product updated = productRepository.save(existingProduct);
                    return productMapper.toDto(updated);
                })
                .orElseThrow(() -> new RuntimeException("Produit non trouvé avec l'id: " + id));
    }

    @Override
    public void delete(Long id) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Produit non trouvé avec l'id: " + id));
        productRepository.delete(product);
    }


    @Override
    public ProductDTO activate(Long id) {
        return productRepository.findById(id)
                .map(product -> {
                    product.setActive(true);
                    product.setStatus(ProductStatus.ACTIVE);
                    product.setLastModifiedDate(LocalDateTime.now());
                    Product updated = productRepository.save(product);
                    return productMapper.toDto(updated);
                })
                .orElseThrow(() -> new RuntimeException("Produit non trouvé avec l'id: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existsByCode(String code) {
        return productRepository.existsByCode(code);
    }

    @Override
    public ProductDTO deactivate(Long id) {
          if(productRepository.countBySalesProductId(id)>0){
              throw new RuntimeException("il ya deja une commande lie a ce produit");
          }

          if(productRepository.existsBackorderedLine(id)){
              throw new RuntimeException("le produit est deja reserve");
          }

        return productRepository.findById(id)
                .map(product -> {
                    product.setActive(false);
                    product.setStatus(ProductStatus.INACTIVE);
                    product.setLastModifiedDate(LocalDateTime.now());
                    Product updated = productRepository.save(product);
                    return productMapper.toDto(updated);
                })
                .orElseThrow(() -> new RuntimeException("Produit non trouvé avec l'id: " + id));
    }
}
