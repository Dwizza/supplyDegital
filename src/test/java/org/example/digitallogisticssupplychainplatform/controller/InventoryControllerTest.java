package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.InventoryDTO;
import org.example.digitallogisticssupplychainplatform.service.InventoryService;
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
@DisplayName("Tests - InventoryController")
class InventoryControllerTest {

    @Mock
    private InventoryService inventoryService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private InventoryDTO testInventory1;
    private InventoryDTO testInventory2;
    private List<InventoryDTO> testInventories;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new InventoryController(inventoryService)
        ).build();

        objectMapper = new ObjectMapper();

        testInventory1 = InventoryDTO.builder()
                .id(1L)
                .productId(1L)
                .warehouseId(1L)
                .qtyOnHand(100)
                .qtyReserved(20)
                .build();

        testInventory2 = InventoryDTO.builder()
                .id(2L)
                .productId(2L)
                .warehouseId(2L)
                .qtyOnHand(50)
                .qtyReserved(10)
                .build();

        testInventories = new ArrayList<>();
        testInventories.add(testInventory1);
        testInventories.add(testInventory2);
    }



    @Test
    @DisplayName("✓ GET /all - Récupérer tous les inventaires")
    void testGetAllInventories() throws Exception {
        when(inventoryService.findAll()).thenReturn(testInventories);

        mockMvc.perform(get("/api/inventories"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[1].id").value(2));

        verify(inventoryService, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ GET /all - Liste vide")
    void testGetAllInventoriesEmpty() throws Exception {
        when(inventoryService.findAll()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/inventories"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(inventoryService, times(1)).findAll();
    }



    @Test
    @DisplayName("✓ GET /{id} - Récupérer inventaire par ID")
    void testGetInventoryById() throws Exception {
        when(inventoryService.findById(1L)).thenReturn(Optional.of(testInventory1));

        mockMvc.perform(get("/api/inventories/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.qtyOnHand").value(100))
                .andExpect(jsonPath("$.qtyReserved").value(20));

        verify(inventoryService, times(1)).findById(1L);
    }

    @Test
    @DisplayName("❌ GET /{id} - Inventaire non trouvé")
    void testGetInventoryByIdNotFound() throws Exception {
        when(inventoryService.findById(999L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/inventories/999"))
                .andExpect(status().isNotFound());

        verify(inventoryService, times(1)).findById(999L);
    }



    @Test
    @DisplayName("✓ POST / - Créer un inventaire")
    void testCreateInventory() throws Exception {
        when(inventoryService.save(any(InventoryDTO.class))).thenReturn(testInventory1);

        String requestBody = objectMapper.writeValueAsString(testInventory1);

        mockMvc.perform(post("/api/inventories")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.qtyOnHand").value(100));

        verify(inventoryService, times(1)).save(any(InventoryDTO.class));
    }

    @Test
    @DisplayName("✓ POST / - Créer autre inventaire")
    void testCreateInventoryAnother() throws Exception {
        when(inventoryService.save(any(InventoryDTO.class))).thenReturn(testInventory2);

        String requestBody = objectMapper.writeValueAsString(testInventory2);

        mockMvc.perform(post("/api/inventories")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(2));

        verify(inventoryService, times(1)).save(any(InventoryDTO.class));
    }


    @Test
    @DisplayName("✓ PUT /{id} - Mettre à jour un inventaire")
    void testUpdateInventory() throws Exception {
        InventoryDTO updatedInventory = InventoryDTO.builder()
                .id(1L)
                .productId(1L)
                .warehouseId(1L)
                .qtyOnHand(150)
                .qtyReserved(30)
                .build();

        when(inventoryService.update(eq(1L), any(InventoryDTO.class)))
                .thenReturn(updatedInventory);

        String requestBody = objectMapper.writeValueAsString(updatedInventory);

        mockMvc.perform(put("/api/inventories/1")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.qtyOnHand").value(150))
                .andExpect(jsonPath("$.qtyReserved").value(30));

        verify(inventoryService, times(1)).update(eq(1L), any(InventoryDTO.class));
    }

    @Test
    @DisplayName("❌ PUT /{id} - Inventaire non trouvé")
    void testUpdateInventoryNotFound() throws Exception {
        when(inventoryService.update(eq(999L), any(InventoryDTO.class)))
                .thenThrow(new RuntimeException("Inventory not found"));

        String requestBody = objectMapper.writeValueAsString(testInventory1);

        mockMvc.perform(put("/api/inventories/999")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isNotFound());

        verify(inventoryService, times(1)).update(eq(999L), any(InventoryDTO.class));
    }


    @Test
    @DisplayName("✓ PATCH /{id}/quantities - Mettre à jour les quantités")
    void testUpdateInventoryQuantities() throws Exception {
        InventoryDTO updatedQty = InventoryDTO.builder()
                .id(1L)
                .qtyOnHand(200)
                .qtyReserved(50)
                .build();

        when(inventoryService.updateQuantities(1L, 200, 50))
                .thenReturn(updatedQty);

        mockMvc.perform(patch("/api/inventories/1/quantities")
                        .param("qtyOnHand", "200")
                        .param("qtyReserved", "50"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.qtyOnHand").value(200))
                .andExpect(jsonPath("$.qtyReserved").value(50));

        verify(inventoryService, times(1)).updateQuantities(1L, 200, 50);
    }

    @Test
    @DisplayName("❌ PATCH /{id}/quantities - Inventaire non trouvé")
    void testUpdateInventoryQuantitiesNotFound() throws Exception {
        when(inventoryService.updateQuantities(999L, 200, 50))
                .thenThrow(new RuntimeException("Inventory not found"));

        mockMvc.perform(patch("/api/inventories/999/quantities")
                        .param("qtyOnHand", "200")
                        .param("qtyReserved", "50"))
                .andExpect(status().isNotFound());

        verify(inventoryService, times(1)).updateQuantities(999L, 200, 50);
    }


    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer un inventaire")
    void testDeleteInventory() throws Exception {
        doNothing().when(inventoryService).delete(1L);

        mockMvc.perform(delete("/api/inventories/1"))
                .andExpect(status().isNoContent());

        verify(inventoryService, times(1)).delete(1L);
    }

    @Test
    @DisplayName("❌ DELETE /{id} - Inventaire non trouvé")
    void testDeleteInventoryNotFound() throws Exception {
        doThrow(new RuntimeException("Inventory not found"))
                .when(inventoryService).delete(999L);

        mockMvc.perform(delete("/api/inventories/999"))
                .andExpect(status().isNotFound());

        verify(inventoryService, times(1)).delete(999L);
    }
}