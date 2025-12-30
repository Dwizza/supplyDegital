package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.service.InventoryMovementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - InventoryMovementController")
class InventoryMovementControllerTest {

    private MockMvc mockMvc;

    @Mock
    private InventoryMovementService movementService;

    @InjectMocks
    private InventoryMovementController inventoryMovementController;

    private ObjectMapper objectMapper;
    private InventoryMovementDTO testMovementDTO;

    @BeforeEach
    void setUp() {

        mockMvc = MockMvcBuilders.standaloneSetup(inventoryMovementController)
                .build();

        objectMapper = new ObjectMapper();

        testMovementDTO = new InventoryMovementDTO();
        testMovementDTO.setId(1L);
        testMovementDTO.setInventoryId(1L);
        testMovementDTO.setProductId(1L);
        testMovementDTO.setWarehouseId(1L);
        testMovementDTO.setType("IN");
        testMovementDTO.setQuantity(10);

    }


    @Test
    @DisplayName("✓ GET /api/inventory-movements - Récupérer tous les mouvements")
    void testGetAllMovements() throws Exception {
        List<InventoryMovementDTO> movements = new ArrayList<>();
        movements.add(testMovementDTO);

        when(movementService.findAll()).thenReturn(movements);

        mockMvc.perform(get("/api/inventory-movements")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(1L))
                .andExpect(jsonPath("$[0].type").value("IN"));

        verify(movementService, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ GET /api/inventory-movements - Liste vide")
    void testGetAllMovementsEmpty() throws Exception {
        when(movementService.findAll()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/inventory-movements")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(movementService, times(1)).findAll();
    }


    @Test
    @DisplayName("✓ GET /api/inventory-movements/{id} - Récupérer mouvement par ID")
    void testGetMovementById() throws Exception {
        when(movementService.findById(1L)).thenReturn(testMovementDTO);

        mockMvc.perform(get("/api/inventory-movements/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1L))
                .andExpect(jsonPath("$.type").value("IN"));

        verify(movementService, times(1)).findById(1L);
    }

    @Test
    @DisplayName("❌ GET /api/inventory-movements/{id} - Mouvement non trouvé")
    void testGetMovementByIdNotFound() throws Exception {
        when(movementService.findById(999L))
                .thenThrow(new RuntimeException("Movement not found"));

        mockMvc.perform(get("/api/inventory-movements/999")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());

        verify(movementService, times(1)).findById(999L);
    }


    @Test
    @DisplayName("✓ GET /api/inventory-movements/inventory/{id} - Mouvements par inventaire")
    void testGetMovementsByInventory() throws Exception {
        List<InventoryMovementDTO> movements = new ArrayList<>();
        movements.add(testMovementDTO);

        when(movementService.findByInventoryId(1L)).thenReturn(movements);

        mockMvc.perform(get("/api/inventory-movements/inventory/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].inventoryId").value(1L));

        verify(movementService, times(1)).findByInventoryId(1L);
    }


    @Test
    @DisplayName("✓ GET /api/inventory-movements/product/{id} - Mouvements par produit")
    void testGetMovementsByProduct() throws Exception {
        List<InventoryMovementDTO> movements = new ArrayList<>();
        movements.add(testMovementDTO);

        when(movementService.findByProductId(1L)).thenReturn(movements);

        mockMvc.perform(get("/api/inventory-movements/product/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].productId").value(1L));

        verify(movementService, times(1)).findByProductId(1L);
    }



    @Test
    @DisplayName("✓ GET /api/inventory-movements/warehouse/{id} - Mouvements par entrepôt")
    void testGetMovementsByWarehouse() throws Exception {
        List<InventoryMovementDTO> movements = new ArrayList<>();
        movements.add(testMovementDTO);

        when(movementService.findByWarehouseId(1L)).thenReturn(movements);

        mockMvc.perform(get("/api/inventory-movements/warehouse/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].warehouseId").value(1L));

        verify(movementService, times(1)).findByWarehouseId(1L);
    }



    @Test
    @DisplayName("✓ GET /api/inventory-movements/type/{type} - Mouvements par type")
    void testGetMovementsByType() throws Exception {
        List<InventoryMovementDTO> movements = new ArrayList<>();
        movements.add(testMovementDTO);

        when(movementService.findByType("IN")).thenReturn(movements);

        mockMvc.perform(get("/api/inventory-movements/type/IN")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].type").value("IN"));

        verify(movementService, times(1)).findByType("IN");
    }


    @Test
    @DisplayName("✓ GET /api/inventory-movements/date-range - Mouvements par plage de dates")
    void testGetMovementsByDateRange() throws Exception {
        List<InventoryMovementDTO> movements = new ArrayList<>();
        movements.add(testMovementDTO);

        LocalDateTime startDate = LocalDateTime.now().minusDays(7);
        LocalDateTime endDate = LocalDateTime.now();

        when(movementService.findByDateRange(any(LocalDateTime.class), any(LocalDateTime.class)))
                .thenReturn(movements);

        mockMvc.perform(get("/api/inventory-movements/date-range")
                        .param("startDate", startDate.toString())
                        .param("endDate", endDate.toString())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(1L));

        verify(movementService, times(1)).findByDateRange(any(LocalDateTime.class), any(LocalDateTime.class));
    }


    @Test
    @DisplayName("✓ POST /api/inventory-movements - Créer un mouvement")
    void testCreateMovement() throws Exception {
        when(movementService.createMovement(any(InventoryMovementDTO.class)))
                .thenReturn(testMovementDTO);

        mockMvc.perform(post("/api/inventory-movements")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(testMovementDTO)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1L))
                .andExpect(jsonPath("$.type").value("IN"));

        verify(movementService, times(1)).createMovement(any(InventoryMovementDTO.class));
    }

    @Test
    @DisplayName("❌ POST /api/inventory-movements - Erreur création")
    void testCreateMovementError() throws Exception {
        when(movementService.createMovement(any(InventoryMovementDTO.class)))
                .thenThrow(new RuntimeException("Invalid movement"));

        mockMvc.perform(post("/api/inventory-movements")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(testMovementDTO)))
                .andExpect(status().isBadRequest());

        verify(movementService, times(1)).createMovement(any(InventoryMovementDTO.class));
    }



    @Test
    @DisplayName("✓ DELETE /api/inventory-movements/{id} - Supprimer mouvement")
    void testDeleteMovement() throws Exception {
        doNothing().when(movementService).deleteMovement(1L);

        mockMvc.perform(delete("/api/inventory-movements/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent());

        verify(movementService, times(1)).deleteMovement(1L);
    }

    @Test
    @DisplayName("❌ DELETE /api/inventory-movements/{id} - Mouvement non trouvé")
    void testDeleteMovementNotFound() throws Exception {
        doThrow(new RuntimeException("Movement not found"))
                .when(movementService).deleteMovement(999L);

        mockMvc.perform(delete("/api/inventory-movements/999")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());

        verify(movementService, times(1)).deleteMovement(999L);
    }


    @Test
    @DisplayName("✓ GET retourne OK (200)")
    void testGetReturnsOkStatus() throws Exception {
        when(movementService.findAll()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/inventory-movements")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("✓ POST retourne CREATED (201)")
    void testPostReturnsCreatedStatus() throws Exception {
        when(movementService.createMovement(any(InventoryMovementDTO.class)))
                .thenReturn(testMovementDTO);

        mockMvc.perform(post("/api/inventory-movements")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(testMovementDTO)))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("✓ DELETE retourne NO_CONTENT (204)")
    void testDeleteReturnsNoContentStatus() throws Exception {
        doNothing().when(movementService).deleteMovement(1L);

        mockMvc.perform(delete("/api/inventory-movements/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent());
    }


    @Test
    @DisplayName("✓ Opérations multiples - Créer et récupérer")
    void testCreateAndGet() throws Exception {
        when(movementService.createMovement(any(InventoryMovementDTO.class)))
                .thenReturn(testMovementDTO);

        mockMvc.perform(post("/api/inventory-movements")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(testMovementDTO)))
                .andExpect(status().isCreated());

        when(movementService.findById(1L)).thenReturn(testMovementDTO);

        mockMvc.perform(get("/api/inventory-movements/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1L));
    }
}