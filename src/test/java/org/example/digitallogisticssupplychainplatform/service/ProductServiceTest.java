package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.ProductDTO;
import org.example.digitallogisticssupplychainplatform.entity.Product;
import org.example.digitallogisticssupplychainplatform.entity.ProductStatus;
import org.example.digitallogisticssupplychainplatform.mapper.ProductMapper;
import org.example.digitallogisticssupplychainplatform.repository.ProductRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@DisplayName("ProductService Unit Tests")
class ProductServiceTest {

    @Mock
    private ProductRepository productRepository;

    @Mock
    private ProductMapper productMapper;

    @InjectMocks
    private ProductServiceImpl productService;

    private ProductDTO productDTO;
    private Product product;
    private Product activeProduct;
    private ProductDTO activeProductDTO;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        productDTO = ProductDTO.builder()
                .id(1L)
                .code("PROD001")
                .name("Produit Test")
                .description("Description du produit")
                .mainStyle("Style1")
                .optionLevel(2)
                .category("Électronique")
                .configuration("Config1")
                .base("Base1")
                .actualEmail("email@test.com")
                .active(true)
                .index(false)
                .profile("Profile1")
                .status("ACTIVE")
                .build();

        product = Product.builder()
                .id(1L)
                .code("PROD001")
                .name("Produit Test")
                .description("Description du produit")
                .mainStyle("Style1")
                .optionLevel(2)
                .category("Électronique")
                .configuration("Config1")
                .base("Base1")
                .actualEmail("email@test.com")
                .active(true)
                .index(false)
                .profile("Profile1")
                .status(ProductStatus.ACTIVE)
                .createdDate(LocalDateTime.now())
                .lastModifiedDate(LocalDateTime.now())
                .build();

        activeProduct = Product.builder()
                .id(2L)
                .code("PROD002")
                .name("Produit Actif")
                .description("Produit actif")
                .active(true)
                .status(ProductStatus.ACTIVE)
                .createdDate(LocalDateTime.now())
                .lastModifiedDate(LocalDateTime.now())
                .build();

        activeProductDTO = ProductDTO.builder()
                .id(2L)
                .code("PROD002")
                .name("Produit Actif")
                .description("Produit actif")
                .active(true)
                .status("ACTIVE")
                .build();
    }


    @Test
    @DisplayName("Should return all products")
    void testFindAll_Success() {
        List<Product> products = Arrays.asList(product, activeProduct);
        List<ProductDTO> expectedDTOs = Arrays.asList(productDTO, activeProductDTO);

        when(productRepository.findAll()).thenReturn(products);
        when(productMapper.toDto(product)).thenReturn(productDTO);
        when(productMapper.toDto(activeProduct)).thenReturn(activeProductDTO);

        List<ProductDTO> result = productService.findAll();

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals(expectedDTOs, result);
        verify(productRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("Should return empty list when no products exist")
    void testFindAll_EmptyList() {
        when(productRepository.findAll()).thenReturn(Arrays.asList());
        List<ProductDTO> result = productService.findAll();
        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(productRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("Should return all active products")
    void testFindAllActive_Success() {
        List<Product> activeProducts = Arrays.asList(product, activeProduct);
        when(productRepository.findAllActive()).thenReturn(activeProducts);
        when(productMapper.toDto(product)).thenReturn(productDTO);
        when(productMapper.toDto(activeProduct)).thenReturn(activeProductDTO);
        List<ProductDTO> result = productService.findAllActive();
        assertNotNull(result);
        assertEquals(2, result.size());
        verify(productRepository, times(1)).findAllActive();
    }

    @Test
    @DisplayName("Should find product by ID successfully")
    void testFindById_Success() {

        when(productRepository.findById(1L)).thenReturn(Optional.of(product));
        when(productMapper.toDto(product)).thenReturn(productDTO);

        Optional<ProductDTO> result = productService.findById(1L);

        assertTrue(result.isPresent());
        assertEquals(productDTO, result.get());
        verify(productRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("Should return empty optional when product not found by ID")
    void testFindById_NotFound() {

        when(productRepository.findById(999L)).thenReturn(Optional.empty());


        Optional<ProductDTO> result = productService.findById(999L);

        assertFalse(result.isPresent());
        verify(productRepository, times(1)).findById(999L);
    }

    @Test
    @DisplayName("Should find product by code successfully")
    void testFindByCode_Success() {
        when(productRepository.findByCode("PROD001")).thenReturn(Optional.of(product));
        when(productMapper.toDto(product)).thenReturn(productDTO);

        Optional<ProductDTO> result = productService.findByCode("PROD001");

        assertTrue(result.isPresent());
        assertEquals(productDTO, result.get());
        verify(productRepository, times(1)).findByCode("PROD001");
    }

    @Test
    @DisplayName("Should return empty optional when product code not found")
    void testFindByCode_NotFound() {

        when(productRepository.findByCode("INVALID_CODE")).thenReturn(Optional.empty());


        Optional<ProductDTO> result = productService.findByCode("INVALID_CODE");


        assertFalse(result.isPresent());
        verify(productRepository, times(1)).findByCode("INVALID_CODE");
    }


    @Test
    @DisplayName("Should find products by category successfully")
    void testFindByCategory_Success() {

        List<Product> categoryProducts = Arrays.asList(product);
        when(productRepository.findByCategory("Électronique")).thenReturn(categoryProducts);
        when(productMapper.toDto(product)).thenReturn(productDTO);


        List<ProductDTO> result = productService.findByCategory("Électronique");

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(productDTO, result.get(0));
        verify(productRepository, times(1)).findByCategory("Électronique");
    }

    @Test
    @DisplayName("Should return empty list for non-existing category")
    void testFindByCategory_EmptyResult() {

        when(productRepository.findByCategory("Inexistant")).thenReturn(Arrays.asList());


        List<ProductDTO> result = productService.findByCategory("Inexistant");


        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(productRepository, times(1)).findByCategory("Inexistant");
    }
    @Test
    @DisplayName("Should save product successfully")
    void testSave_Success() {
        when(productRepository.existsByCode("PROD001")).thenReturn(false);
        when(productMapper.toEntity(productDTO)).thenReturn(product);
        when(productRepository.save(product)).thenReturn(product);
        when(productMapper.toDto(product)).thenReturn(productDTO);
        ProductDTO result = productService.save(productDTO);
        assertNotNull(result);
        assertEquals(productDTO, result);
        verify(productRepository, times(1)).existsByCode("PROD001");
        verify(productRepository, times(1)).save(product);
    }

    @Test
    @DisplayName("Should throw exception when saving product with duplicate code")
    void testSave_DuplicateCode() {
        when(productRepository.existsByCode("PROD001")).thenReturn(true);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            productService.save(productDTO);
        });

        assertTrue(exception.getMessage().contains("existe déjà"));
        verify(productRepository, times(1)).existsByCode("PROD001");
        verify(productRepository, never()).save(any());
    }
    @Test
    @DisplayName("Should update product successfully")
    void testUpdate_Success() {

        ProductDTO updateDTO = ProductDTO.builder()
                .code("PROD001")
                .name("Produit Modifié")
                .description("Description modifiée")
                .build();

        when(productRepository.findById(1L)).thenReturn(Optional.of(product));
        when(productRepository.existsByCode("PROD001")).thenReturn(false);
        when(productRepository.save(any(Product.class))).thenReturn(product);
        when(productMapper.toDto(product)).thenReturn(productDTO);


        ProductDTO result = productService.update(1L, updateDTO);

        assertNotNull(result);
        verify(productRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).save(any(Product.class));
    }

    @Test
    @DisplayName("Should throw exception when updating non-existing product")
    void testUpdate_NotFound() {

        when(productRepository.findById(999L)).thenReturn(Optional.empty());


        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            productService.update(999L, productDTO);
        });

        assertTrue(exception.getMessage().contains("non trouvé"));
        verify(productRepository, times(1)).findById(999L);
        verify(productRepository, never()).save(any());
    }

    @Test
    @DisplayName("Should throw exception when updating product with duplicate code")
    void testUpdate_DuplicateCode() {

        ProductDTO updateDTO = ProductDTO.builder()
                .code("PROD002")
                .name("Produit Modifié")
                .build();

        when(productRepository.findById(1L)).thenReturn(Optional.of(product));
        when(productRepository.existsByCode("PROD002")).thenReturn(true);


        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            productService.update(1L, updateDTO);
        });

        assertTrue(exception.getMessage().contains("existe déjà"));
        verify(productRepository, never()).save(any());
    }

    @Test
    @DisplayName("Should delete product successfully")
    void testDelete_Success() {

        when(productRepository.findById(1L)).thenReturn(Optional.of(product));

        productService.delete(1L);

        verify(productRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).delete(product);
    }

    @Test
    @DisplayName("Should throw exception when deleting non-existing product")
    void testDelete_NotFound() {

        when(productRepository.findById(999L)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            productService.delete(999L);
        });

        assertTrue(exception.getMessage().contains("non trouvé"));
        verify(productRepository, never()).delete(any());
    }

    @Test
    @DisplayName("Should activate product successfully")
    void testActivate_Success() {

        Product inactiveProduct = Product.builder()
                .id(1L)
                .code("PROD001")
                .name("Produit Test")
                .active(false)
                .status(ProductStatus.INACTIVE)
                .build();

        ProductDTO activatedDTO = ProductDTO.builder()
                .id(1L)
                .code("PROD001")
                .active(true)
                .status("ACTIVE")
                .build();

        when(productRepository.findById(1L)).thenReturn(Optional.of(inactiveProduct));
        when(productRepository.save(any(Product.class))).thenReturn(inactiveProduct);
        when(productMapper.toDto(inactiveProduct)).thenReturn(activatedDTO);

        ProductDTO result = productService.activate(1L);

        assertNotNull(result);
        assertTrue(result.getActive());
        verify(productRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).save(any(Product.class));
    }


    @Test
    @DisplayName("Should deactivate product successfully")
    void testDeactivate_Success() {


        Product activeProduct = Product.builder()
                .id(1L)
                .code("PROD001")
                .name("Produit Test")
                .active(true)
                .status(ProductStatus.ACTIVE)
                .build();

        ProductDTO deactivatedDTO = ProductDTO.builder()
                .id(1L)
                .code("PROD001")
                .active(false)
                .status("INACTIVE")
                .build();

        when(productRepository.findById(1L)).thenReturn(Optional.of(activeProduct));
        when(productRepository.countBySalesProductId(1L)).thenReturn(0L);
        when(productRepository.existsBackorderedLine(1L)).thenReturn(false);
        when(productRepository.save(any(Product.class))).thenReturn(activeProduct);
        when(productMapper.toDto(activeProduct)).thenReturn(deactivatedDTO);

        ProductDTO result = productService.deactivate(1L);

        assertNotNull(result);
        assertFalse(result.getActive());
        verify(productRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).save(any(Product.class));
    }

    @Test
    @DisplayName("Should not deactivate product with existing sales orders")
    void testDeactivate_WithSalesOrders() {

        Product product = Product.builder()
                .id(1L)
                .code("PROD001")
                .active(true)
                .build();

        when(productRepository.findById(1L)).thenReturn(Optional.of(product));
        when(productRepository.countBySalesProductId(1L)).thenReturn(5L);


        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            productService.deactivate(1L);
        });

        assertTrue(exception.getMessage().contains("deja une commande"));
        verify(productRepository, never()).save(any());
    }

    @Test
    @DisplayName("Should not deactivate product with backorders")
    void testDeactivate_WithBackorders() {

        Product product = Product.builder()
                .id(1L)
                .code("PROD001")
                .active(true)
                .build();

        when(productRepository.findById(1L)).thenReturn(Optional.of(product));
        when(productRepository.countBySalesProductId(1L)).thenReturn(0L);
        when(productRepository.existsBackorderedLine(1L)).thenReturn(true);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            productService.deactivate(1L);
        });

        assertTrue(exception.getMessage().contains("deja reserve"));
        verify(productRepository, never()).save(any());
    }

    @Test
    @DisplayName("Should return true when product code exists")
    void testExistsByCode_True() {

        when(productRepository.existsByCode("PROD001")).thenReturn(true);


        boolean result = productService.existsByCode("PROD001");

        assertTrue(result);
        verify(productRepository, times(1)).existsByCode("PROD001");
    }

    @Test
    @DisplayName("Should return false when product code does not exist")
    void testExistsByCode_False() {
        when(productRepository.existsByCode("INVALID")).thenReturn(false);
        boolean result = productService.existsByCode("INVALID");
        assertFalse(result);
        verify(productRepository, times(1)).existsByCode("INVALID");
    }
}