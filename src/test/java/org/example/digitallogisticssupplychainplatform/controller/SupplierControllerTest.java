package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.SupplierDTO;
import org.example.digitallogisticssupplychainplatform.service.SupplierService;
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
@DisplayName("Tests - SupplierController")
class SupplierControllerTest {

    @Mock
    private SupplierService supplierService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private SupplierDTO testSupplier1;
    private SupplierDTO testSupplier2;
    private List<SupplierDTO> testSuppliers;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new SupplierController(supplierService)
        ).build();

        objectMapper = new ObjectMapper();

        testSupplier1 = SupplierDTO.builder()
                .id(1L)
                .name("Supplier A")

                .build();

        testSupplier2 = SupplierDTO.builder()
                .id(2L)
                .name("Supplier B")
                .build();

        testSuppliers = new ArrayList<>();
        testSuppliers.add(testSupplier1);
        testSuppliers.add(testSupplier2);
    }



    @Test
    @DisplayName("✓ POST / - Créer un fournisseur")
    void testCreateSupplier() throws Exception {
        when(supplierService.save(any(SupplierDTO.class))).thenReturn(testSupplier1);

        String requestBody = objectMapper.writeValueAsString(testSupplier1);

        mockMvc.perform(post("/api/suppliers")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Supplier A"));

        verify(supplierService, times(1)).save(any(SupplierDTO.class));
    }

    @Test
    @DisplayName("✓ POST / - Créer autre fournisseur")
    void testCreateSupplierAnother() throws Exception {
        when(supplierService.save(any(SupplierDTO.class))).thenReturn(testSupplier2);

        String requestBody = objectMapper.writeValueAsString(testSupplier2);

        mockMvc.perform(post("/api/suppliers")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Supplier B"));

        verify(supplierService, times(1)).save(any(SupplierDTO.class));
    }


    @Test
    @DisplayName("✓ GET / - Récupérer tous les fournisseurs")
    void testGetAllSuppliers() throws Exception {
        when(supplierService.findAll()).thenReturn(testSuppliers);

        mockMvc.perform(get("/api/suppliers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].name").value("Supplier A"))
                .andExpect(jsonPath("$[1].name").value("Supplier B"));

        verify(supplierService, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ GET / - Liste vide")
    void testGetAllSuppliersEmpty() throws Exception {
        when(supplierService.findAll()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/suppliers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(supplierService, times(1)).findAll();
    }



    @Test
    @DisplayName("✓ GET /{id} - Récupérer fournisseur par ID")
    void testFindBySupplierId() throws Exception {
        when(supplierService.findById(1L)).thenReturn(testSupplier1);

        mockMvc.perform(get("/api/suppliers/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Supplier A"));

        verify(supplierService, times(1)).findById(1L);
    }

    @Test
    @DisplayName("✓ GET /{id} - Récupérer autre fournisseur")
    void testFindBySupplierIdAnother() throws Exception {
        when(supplierService.findById(2L)).thenReturn(testSupplier2);

        mockMvc.perform(get("/api/suppliers/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Supplier B"));

        verify(supplierService, times(1)).findById(2L);
    }

    @Test
    @DisplayName("❌ GET /{id} - Erreur lors de la récupération")
    void testFindBySupplierIdError() throws Exception {
        when(supplierService.findById(999L))
                .thenThrow(new RuntimeException("Supplier not found"));

        mockMvc.perform(get("/api/suppliers/999"))
                .andExpect(status().isBadRequest());

        verify(supplierService, times(1)).findById(999L);
    }



    @Test
    @DisplayName("✓ GET /name/{name} - Récupérer fournisseur par nom")
    void testFindBySupplierName() throws Exception {
        when(supplierService.findByName("Supplier A")).thenReturn(Optional.of(testSupplier1));

        mockMvc.perform(get("/api/suppliers/name/Supplier A"))
                .andExpect(status().isOk());

        verify(supplierService, times(1)).findByName("Supplier A");
    }

    @Test
    @DisplayName("✓ GET /name/{name} - Fournisseur non trouvé")
    void testFindBySupplierNameNotFound() throws Exception {
        when(supplierService.findByName("Unknown"))
                .thenReturn(Optional.empty());

        mockMvc.perform(get("/api/suppliers/name/Unknown"))
                .andExpect(status().isOk());

        verify(supplierService, times(1)).findByName("Unknown");
    }

    @Test
    @DisplayName("❌ GET /name/{name} - Erreur")
    void testFindBySupplierNameError() throws Exception {
        when(supplierService.findByName("Test"))
                .thenThrow(new RuntimeException("Database error"));

        mockMvc.perform(get("/api/suppliers/name/Test"))
                .andExpect(status().isBadRequest());

        verify(supplierService, times(1)).findByName("Test");
    }



    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer un fournisseur")
    void testRemoveSupplier() throws Exception {
        doNothing().when(supplierService).deleteById(1L);

        mockMvc.perform(delete("/api/suppliers/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("supplier deleted succesefly"));

        verify(supplierService, times(1)).deleteById(1L);
    }

    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer autre fournisseur")
    void testRemoveSupplierAnother() throws Exception {
        doNothing().when(supplierService).deleteById(2L);

        mockMvc.perform(delete("/api/suppliers/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists());

        verify(supplierService, times(1)).deleteById(2L);
    }



    @Test
    @DisplayName("✓ PUT /{id} - Mettre à jour un fournisseur")
    void testUpdateSupplier() throws Exception {
        SupplierDTO updatedSupplier = SupplierDTO.builder()
                .id(1L)
                .name("Supplier A Updated")
                .build();

        when(supplierService.updateSupplier(eq(1L), any(SupplierDTO.class)))
                .thenReturn(updatedSupplier);

        String requestBody = objectMapper.writeValueAsString(updatedSupplier);

        mockMvc.perform(put("/api/suppliers/1")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Supplier A Updated"));

        verify(supplierService, times(1)).updateSupplier(eq(1L), any(SupplierDTO.class));
    }

    @Test
    @DisplayName("✓ PUT /{id} - Mettre à jour autre fournisseur")
    void testUpdateSupplierAnother() throws Exception {
        SupplierDTO updatedSupplier = SupplierDTO.builder()
                .id(2L)
                .name("Supplier B Updated")
                .build();

        when(supplierService.updateSupplier(eq(2L), any(SupplierDTO.class)))
                .thenReturn(updatedSupplier);

        String requestBody = objectMapper.writeValueAsString(updatedSupplier);

        mockMvc.perform(put("/api/suppliers/2")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Supplier B Updated"));

        verify(supplierService, times(1)).updateSupplier(eq(2L), any(SupplierDTO.class));
    }

    @Test
    @DisplayName("❌ PUT /{id} - Erreur lors de la mise à jour")
    void testUpdateSupplierError() throws Exception {
        when(supplierService.updateSupplier(eq(999L), any(SupplierDTO.class)))
                .thenThrow(new RuntimeException("Supplier not found"));

        String requestBody = objectMapper.writeValueAsString(testSupplier1);

        mockMvc.perform(put("/api/suppliers/999")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());

        verify(supplierService, times(1)).updateSupplier(eq(999L), any(SupplierDTO.class));
    }
}