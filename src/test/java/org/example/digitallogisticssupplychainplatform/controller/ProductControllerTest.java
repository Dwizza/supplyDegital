package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.ProductDTO;
import org.example.digitallogisticssupplychainplatform.service.ProductService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - ProductController")
class ProductControllerTest {

    @Mock
    private ProductService productService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private ProductDTO testProduct1;
    private ProductDTO testProduct2;
    private List<ProductDTO> testProducts;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new ProductController(productService)
        ).build();

        objectMapper = new ObjectMapper();

        testProduct1 = ProductDTO.builder()
                .id(1L)
                .code("PROD-001")
                .name("Laptop")
                .description("High performance laptop")
                .category("Electronics")
                .active(true)
                .build();

        testProduct2 = ProductDTO.builder()
                .id(2L)
                .code("PROD-002")
                .name("Monitor")
                .description("4K Monitor")
                .category("Electronics")

                .active(true)
                .build();

        testProducts = new ArrayList<>();
        testProducts.add(testProduct1);
        testProducts.add(testProduct2);
    }



    @Test
    @DisplayName("✓ GET / - Récupérer tous les produits")
    void testGetAllProducts() throws Exception {
        when(productService.findAll()).thenReturn(testProducts);

        mockMvc.perform(get("/api/products"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].code").value("PROD-001"))
                .andExpect(jsonPath("$[1].code").value("PROD-002"));

        verify(productService, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ GET /?category=Electronics - Récupérer par catégorie")
    void testGetProductsByCategory() throws Exception {
        when(productService.findByCategory("Electronics")).thenReturn(testProducts);

        mockMvc.perform(get("/api/products")
                        .param("category", "Electronics"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2));

        verify(productService, times(1)).findByCategory("Electronics");
    }

    @Test
    @DisplayName("✓ GET /?active=true - Récupérer produits actifs")
    void testGetActiveProducts() throws Exception {
        when(productService.findAllActive()).thenReturn(testProducts);

        mockMvc.perform(get("/api/products")
                        .param("active", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2));

        verify(productService, times(1)).findAllActive();
    }



    @Test
    @DisplayName("✓ GET /{id} - Récupérer produit par ID")
    void testGetProductById() throws Exception {
        when(productService.findById(1L)).thenReturn(Optional.of(testProduct1));

        mockMvc.perform(get("/api/products/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.code").value("PROD-001"))
                .andExpect(jsonPath("$.name").value("Laptop"));

        verify(productService, times(1)).findById(1L);
    }

    @Test
    @DisplayName("❌ GET /{id} - Produit non trouvé")
    void testGetProductByIdNotFound() throws Exception {
        when(productService.findById(999L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/products/999"))
                .andExpect(status().isNotFound());

        verify(productService, times(1)).findById(999L);
    }


    @Test
    @DisplayName("✓ GET /code/{code} - Récupérer produit par code")
    void testGetProductByCode() throws Exception {
        when(productService.findByCode("PROD-001")).thenReturn(Optional.of(testProduct1));

        mockMvc.perform(get("/api/products/code/PROD-001"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("PROD-001"))
                .andExpect(jsonPath("$.name").value("Laptop"));

        verify(productService, times(1)).findByCode("PROD-001");
    }

    @Test
    @DisplayName("❌ GET /code/{code} - Produit non trouvé")
    void testGetProductByCodeNotFound() throws Exception {
        when(productService.findByCode("INVALID")).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/products/code/INVALID"))
                .andExpect(status().isNotFound());

        verify(productService, times(1)).findByCode("INVALID");
    }



    @Test
    @DisplayName("✓ POST / - Créer un produit")
    void testCreateProduct() throws Exception {
        when(productService.save(any(ProductDTO.class))).thenReturn(testProduct1);

        String requestBody = objectMapper.writeValueAsString(testProduct1);

        mockMvc.perform(post("/api/products")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.code").value("PROD-001"));

        verify(productService, times(1)).save(any(ProductDTO.class));
    }


    @Test
    @DisplayName("✓ PUT /{id} - Mettre à jour un produit")
    void testUpdateProduct() throws Exception {
        ProductDTO updatedProduct = ProductDTO.builder()
                .id(1L)
                .code("PROD-001")
                .name("Updated Laptop")
                .active(true)
                .build();

        when(productService.update(eq(1L), any(ProductDTO.class)))
                .thenReturn(updatedProduct);

        String requestBody = objectMapper.writeValueAsString(updatedProduct);

        mockMvc.perform(put("/api/products/1")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Updated Laptop"));

        verify(productService, times(1)).update(eq(1L), any(ProductDTO.class));
    }

    @Test
    @DisplayName("❌ PUT /{id} - Produit non trouvé")
    void testUpdateProductNotFound() throws Exception {
        when(productService.update(eq(999L), any(ProductDTO.class)))
                .thenThrow(new RuntimeException("Product not found"));

        String requestBody = objectMapper.writeValueAsString(testProduct1);

        mockMvc.perform(put("/api/products/999")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isNotFound());

        verify(productService, times(1)).update(eq(999L), any(ProductDTO.class));
    }


    @Test
    @DisplayName("✓ PATCH /{id}/activate - Activer un produit")
    void testActivateProduct() throws Exception {
        ProductDTO activatedProduct = ProductDTO.builder()
                .id(1L)
                .code("PROD-001")
                .name("Laptop")
                .active(true)
                .build();

        when(productService.activate(1L)).thenReturn(activatedProduct);

        mockMvc.perform(patch("/api/products/1/activate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true));

        verify(productService, times(1)).activate(1L);
    }


    @Test
    @DisplayName("✓ PATCH /{id}/deactivate - Désactiver un produit")
    void testDeactivateProduct() throws Exception {
        ProductDTO deactivatedProduct = ProductDTO.builder()
                .id(1L)
                .code("PROD-001")
                .name("Laptop")
                .active(false)
                .build();

        when(productService.deactivate(1L)).thenReturn(deactivatedProduct);

        mockMvc.perform(patch("/api/products/1/deactivate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));

        verify(productService, times(1)).deactivate(1L);
    }

    @Test
    @DisplayName("❌ PATCH /{id}/deactivate - Produit non trouvé")
    void testDeactivateProductNotFound() throws Exception {
        when(productService.deactivate(999L))
                .thenThrow(new RuntimeException("Product not found"));

        mockMvc.perform(patch("/api/products/999/deactivate"))
                .andExpect(status().isOk());

        verify(productService, times(1)).deactivate(999L);
    }



    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer un produit")
    void testDeleteProduct() throws Exception {
        doNothing().when(productService).delete(1L);

        mockMvc.perform(delete("/api/products/1"))
                .andExpect(status().isNoContent());

        verify(productService, times(1)).delete(1L);
    }

    @Test
    @DisplayName("❌ DELETE /{id} - Produit non trouvé")
    void testDeleteProductNotFound() throws Exception {
        doThrow(new RuntimeException("Product not found"))
                .when(productService).delete(999L);

        mockMvc.perform(delete("/api/products/999"))
                .andExpect(status().isNotFound());

        verify(productService, times(1)).delete(999L);
    }
}