package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.ProductDTO;
import org.example.digitallogisticssupplychainplatform.entity.Product;
import org.example.digitallogisticssupplychainplatform.entity.ProductStatus;
import org.example.digitallogisticssupplychainplatform.mapper.ProductMapper;
import org.example.digitallogisticssupplychainplatform.repository.ProductRepository;
import org.example.digitallogisticssupplychainplatform.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - ProductServiceImpl")
class ProductServiceImplTest {

    @Mock
    private ProductRepository productRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private ProductMapper productMapper;

    private ProductServiceImpl productService;

    private Product testProduct;
    private ProductDTO testProductDTO;

    @BeforeEach
    void setUp() {
        productService = new ProductServiceImpl(
                productRepository,
                userRepository,
                productMapper
        );

        testProduct = new Product();
        testProduct.setId(1L);
        testProduct.setCode("PROD-001");
        testProduct.setName("Product 1");
        testProduct.setDescription("Test product");
        testProduct.setActive(true);
        testProduct.setStatus(ProductStatus.ACTIVE);

        testProductDTO = new ProductDTO();
        testProductDTO.setId(1L);
        testProductDTO.setCode("PROD-001");
        testProductDTO.setName("Product 1");
        testProductDTO.setDescription("Test product");
        testProductDTO.setActive(true);
    }

    // ============================================================
    // TEST: findAll
    // ============================================================

    @Test
    @DisplayName("✓ findAll - Récupérer tous les produits")
    void testFindAll() {
        List<Product> products = new ArrayList<>();
        products.add(testProduct);

        when(productRepository.findAll()).thenReturn(products);
        when(productMapper.toDto(testProduct)).thenReturn(testProductDTO);

        List<ProductDTO> result = productService.findAll();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(productRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ findAll - Liste vide")
    void testFindAllEmpty() {
        when(productRepository.findAll()).thenReturn(new ArrayList<>());

        List<ProductDTO> result = productService.findAll();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(productRepository, times(1)).findAll();
    }

    // ============================================================
    // TEST: findAllActive
    // ============================================================

    @Test
    @DisplayName("✓ findAllActive - Récupérer produits actifs")
    void testFindAllActive() {
        List<Product> products = new ArrayList<>();
        products.add(testProduct);

        when(productRepository.findAllActive()).thenReturn(products);
        when(productMapper.toDto(testProduct)).thenReturn(testProductDTO);

        List<ProductDTO> result = productService.findAllActive();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(productRepository, times(1)).findAllActive();
    }

    // ============================================================
    // TEST: findById
    // ============================================================

    @Test
    @DisplayName("✓ findById - Récupérer produit par ID")
    void testFindById() {
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(productMapper.toDto(testProduct)).thenReturn(testProductDTO);

        Optional<ProductDTO> result = productService.findById(1L);

        assertTrue(result.isPresent());
        assertEquals(1L, result.get().getId());
        verify(productRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("✓ findById - Produit non trouvé")
    void testFindByIdNotFound() {
        when(productRepository.findById(999L)).thenReturn(Optional.empty());

        Optional<ProductDTO> result = productService.findById(999L);

        assertFalse(result.isPresent());
        verify(productRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: findByCode
    // ============================================================

    @Test
    @DisplayName("✓ findByCode - Récupérer produit par code")
    void testFindByCode() {
        when(productRepository.findByCode("PROD-001")).thenReturn(Optional.of(testProduct));
        when(productMapper.toDto(testProduct)).thenReturn(testProductDTO);

        Optional<ProductDTO> result = productService.findByCode("PROD-001");

        assertTrue(result.isPresent());
        assertEquals("PROD-001", result.get().getCode());
        verify(productRepository, times(1)).findByCode("PROD-001");
    }

    // ============================================================
    // TEST: findByCategory
    // ============================================================

    @Test
    @DisplayName("✓ findByCategory - Récupérer produits par catégorie")
    void testFindByCategory() {
        List<Product> products = new ArrayList<>();
        products.add(testProduct);

        when(productRepository.findByCategory("Electronics")).thenReturn(products);
        when(productMapper.toDto(testProduct)).thenReturn(testProductDTO);

        List<ProductDTO> result = productService.findByCategory("Electronics");

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(productRepository, times(1)).findByCategory("Electronics");
    }

    // ============================================================
    // TEST: save
    // ============================================================

    @Test
    @DisplayName("✓ save - Créer un nouveau produit")
    void testSaveSuccess() {
        ProductDTO createDto = new ProductDTO();
        createDto.setCode("PROD-002");
        createDto.setName("Product 2");

        when(productRepository.existsByCode("PROD-002")).thenReturn(false);
        when(productMapper.toEntity(createDto)).thenReturn(testProduct);
        when(productRepository.save(any(Product.class))).thenReturn(testProduct);
        when(productMapper.toDto(testProduct)).thenReturn(testProductDTO);

        ProductDTO result = productService.save(createDto);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(productRepository, times(1)).existsByCode("PROD-002");
        verify(productRepository, times(1)).save(any(Product.class));
    }

    @Test
    @DisplayName("❌ save - Code produit dupliqué")
    void testSaveDuplicateCode() {
        ProductDTO createDto = new ProductDTO();
        createDto.setCode("PROD-001");

        when(productRepository.existsByCode("PROD-001")).thenReturn(true);

        assertThrows(RuntimeException.class, () -> productService.save(createDto));
        verify(productRepository, times(1)).existsByCode("PROD-001");
        verify(productRepository, never()).save(any());
    }

    // ============================================================
    // TEST: update
    // ============================================================

    @Test
    @DisplayName("✓ update - Mettre à jour produit")
    void testUpdateSuccess() {
        ProductDTO updateDto = new ProductDTO();
        updateDto.setCode("PROD-001");
        updateDto.setName("Updated Product");
        updateDto.setDescription("Updated description");

        Product updatedProduct = new Product();
        updatedProduct.setId(1L);
        updatedProduct.setName("Updated Product");

        ProductDTO resultDto = new ProductDTO();
        resultDto.setId(1L);
        resultDto.setName("Updated Product");

        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(productRepository.save(any(Product.class))).thenReturn(updatedProduct);
        when(productMapper.toDto(updatedProduct)).thenReturn(resultDto);

        ProductDTO result = productService.update(1L, updateDto);

        assertNotNull(result);
        assertEquals("Updated Product", result.getName());
        verify(productRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).save(any(Product.class));
    }

    @Test
    @DisplayName("❌ update - Produit non trouvé")
    void testUpdateNotFound() {
        ProductDTO updateDto = new ProductDTO();
        updateDto.setCode("PROD-001");

        when(productRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> productService.update(999L, updateDto));
        verify(productRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: delete
    // ============================================================

    @Test
    @DisplayName("✓ delete - Supprimer produit")
    void testDeleteSuccess() {
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        doNothing().when(productRepository).delete(testProduct);

        productService.delete(1L);

        verify(productRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).delete(testProduct);
    }

    @Test
    @DisplayName("❌ delete - Produit non trouvé")
    void testDeleteNotFound() {
        when(productRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> productService.delete(999L));
        verify(productRepository, times(1)).findById(999L);
        verify(productRepository, never()).delete(any());
    }

    // ============================================================
    // TEST: activate
    // ============================================================

    @Test
    @DisplayName("✓ activate - Activer produit")
    void testActivateSuccess() {
        Product inactiveProduct = new Product();
        inactiveProduct.setId(1L);
        inactiveProduct.setActive(false);
        inactiveProduct.setStatus(ProductStatus.INACTIVE);

        Product activatedProduct = new Product();
        activatedProduct.setId(1L);
        activatedProduct.setActive(true);
        activatedProduct.setStatus(ProductStatus.ACTIVE);

        ProductDTO resultDto = new ProductDTO();
        resultDto.setId(1L);
        resultDto.setActive(true);

        when(productRepository.findById(1L)).thenReturn(Optional.of(inactiveProduct));
        when(productRepository.save(any(Product.class))).thenReturn(activatedProduct);
        when(productMapper.toDto(activatedProduct)).thenReturn(resultDto);

        ProductDTO result = productService.activate(1L);

        assertNotNull(result);
        assertTrue(result.getActive());
        verify(productRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).save(any(Product.class));
    }

    // ============================================================
    // TEST: deactivate
    // ============================================================

    @Test
    @DisplayName("✓ deactivate - Désactiver produit")
    void testDeactivateSuccess() {
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(productRepository.countBySalesProductId(1L)).thenReturn(0L);
        when(productRepository.existsBackorderedLine(1L)).thenReturn(false);

        Product deactivatedProduct = new Product();
        deactivatedProduct.setId(1L);
        deactivatedProduct.setActive(false);
        deactivatedProduct.setStatus(ProductStatus.INACTIVE);

        ProductDTO resultDto = new ProductDTO();
        resultDto.setId(1L);
        resultDto.setActive(false);

        when(productRepository.save(any(Product.class))).thenReturn(deactivatedProduct);
        when(productMapper.toDto(deactivatedProduct)).thenReturn(resultDto);

        ProductDTO result = productService.deactivate(1L);

        assertNotNull(result);
        assertFalse(result.getActive());
        verify(productRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).save(any(Product.class));
    }

    @Test
    @DisplayName("❌ deactivate - Produit avec commandes")
    void testDeactivateWithSales() {
        when(productRepository.countBySalesProductId(1L)).thenReturn(1L);

        assertThrows(RuntimeException.class, () -> productService.deactivate(1L));
        verify(productRepository, times(1)).countBySalesProductId(1L);
        verify(productRepository, never()).findById(any());
    }

    @Test
    @DisplayName("❌ deactivate - Produit réservé")
    void testDeactivateWithBackorder() {
        when(productRepository.countBySalesProductId(1L)).thenReturn(0L);
        when(productRepository.existsBackorderedLine(1L)).thenReturn(true);

        assertThrows(RuntimeException.class, () -> productService.deactivate(1L));
        verify(productRepository, times(1)).countBySalesProductId(1L);
        verify(productRepository, times(1)).existsBackorderedLine(1L);
        verify(productRepository, never()).findById(any());
    }

    // ============================================================
    // TEST: existsByCode
    // ============================================================

    @Test
    @DisplayName("✓ existsByCode - Produit existe")
    void testExistsByCodeTrue() {
        when(productRepository.existsByCode("PROD-001")).thenReturn(true);

        boolean result = productService.existsByCode("PROD-001");

        assertTrue(result);
        verify(productRepository, times(1)).existsByCode("PROD-001");
    }

    @Test
    @DisplayName("✓ existsByCode - Produit n'existe pas")
    void testExistsByCodeFalse() {
        when(productRepository.existsByCode("UNKNOWN")).thenReturn(false);

        boolean result = productService.existsByCode("UNKNOWN");

        assertFalse(result);
        verify(productRepository, times(1)).existsByCode("UNKNOWN");
    }

    // ============================================================
    // TEST: Multiple operations
    // ============================================================

    @Test
    @DisplayName("✓ Opérations multiples - Créer et récupérer")
    void testCreateAndGet() {
        ProductDTO createDto = new ProductDTO();
        createDto.setCode("PROD-002");

        when(productRepository.existsByCode("PROD-002")).thenReturn(false);
        when(productMapper.toEntity(createDto)).thenReturn(testProduct);
        when(productRepository.save(any())).thenReturn(testProduct);
        when(productMapper.toDto(testProduct)).thenReturn(testProductDTO);

        ProductDTO created = productService.save(createDto);
        assertNotNull(created);

        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        Optional<ProductDTO> retrieved = productService.findById(1L);
        assertTrue(retrieved.isPresent());
        assertEquals(created.getId(), retrieved.get().getId());
    }

    @Test
    @DisplayName("✓ Opérations multiples - Créer, activer et désactiver")
    void testCreateActivateAndDeactivate() {
        ProductDTO createDto = new ProductDTO();
        createDto.setCode("PROD-002");

        when(productRepository.existsByCode("PROD-002")).thenReturn(false);
        when(productMapper.toEntity(createDto)).thenReturn(testProduct);
        when(productRepository.save(any())).thenReturn(testProduct);
        when(productMapper.toDto(testProduct)).thenReturn(testProductDTO);

        ProductDTO created = productService.save(createDto);
        assertNotNull(created);

        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        ProductDTO activated = productService.activate(1L);
        assertNotNull(activated);

        when(productRepository.countBySalesProductId(1L)).thenReturn(0L);
        when(productRepository.existsBackorderedLine(1L)).thenReturn(false);
        ProductDTO deactivated = productService.deactivate(1L);
        assertNotNull(deactivated);
    }
}