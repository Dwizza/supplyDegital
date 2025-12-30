package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.CarrierDTO;
import org.example.digitallogisticssupplychainplatform.entity.CarrierStatus;
import org.example.digitallogisticssupplychainplatform.service.CarrierService;
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
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - CarrierController")
class CarrierControllerTest {

    @Mock
    private CarrierService carrierService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private CarrierDTO testCarrier1;
    private CarrierDTO testCarrier2;
    private List<CarrierDTO> testCarriers;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new CarrierController(carrierService)
        ).build();

        objectMapper = new ObjectMapper();

        testCarrier1 = CarrierDTO.builder()
                .name("FedEx")
                .code("FDX")
                .status(CarrierStatus.ACTIVE)
                .build();

        testCarrier2 = CarrierDTO.builder()
                .name("DHL")
                .code("DHL")
                .status(CarrierStatus.ACTIVE)
                .build();

        testCarriers = new ArrayList<>();
        testCarriers.add(testCarrier1);
        testCarriers.add(testCarrier2);
    }


    @Test
    @DisplayName("✓ POST / - Créer un transporteur")
    void testCreateCarrier() throws Exception {
        when(carrierService.save(any(CarrierDTO.class))).thenReturn(testCarrier1);

        String requestBody = objectMapper.writeValueAsString(testCarrier1);

        mockMvc.perform(post("/api/carriers")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("FedEx"));

        verify(carrierService, times(1)).save(any(CarrierDTO.class));
    }

    @Test
    @DisplayName("✓ POST / - Créer autre transporteur")
    void testCreateCarrierAnother() throws Exception {
        when(carrierService.save(any(CarrierDTO.class))).thenReturn(testCarrier2);

        String requestBody = objectMapper.writeValueAsString(testCarrier2);

        mockMvc.perform(post("/api/carriers")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("DHL"));

        verify(carrierService, times(1)).save(any(CarrierDTO.class));
    }

    @Test
    @DisplayName("❌ POST / - Erreur lors de la création")
    void testCreateCarrierError() throws Exception {
        when(carrierService.save(any(CarrierDTO.class)))
                .thenThrow(new RuntimeException("Carrier already exists"));

        String requestBody = objectMapper.writeValueAsString(testCarrier1);

        mockMvc.perform(post("/api/carriers")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isBadRequest());

        verify(carrierService, times(1)).save(any(CarrierDTO.class));
    }


    @Test
    @DisplayName("✓ GET / - Récupérer tous les transporteurs")
    void testGetAllCarriers() throws Exception {
        when(carrierService.findAll()).thenReturn(testCarriers);

        mockMvc.perform(get("/api/carriers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].name").value("FedEx"))
                .andExpect(jsonPath("$[1].name").value("DHL"));

        verify(carrierService, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ GET / - Liste vide")
    void testGetAllCarriersEmpty() throws Exception {
        when(carrierService.findAll()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/carriers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(carrierService, times(1)).findAll();
    }

    @Test
    @DisplayName("❌ GET / - Erreur lors de la récupération")
    void testGetAllCarriersError() throws Exception {
        when(carrierService.findAll())
                .thenThrow(new RuntimeException("Database error"));

        mockMvc.perform(get("/api/carriers"))
                .andExpect(status().isBadRequest());

        verify(carrierService, times(1)).findAll();
    }



    @Test
    @DisplayName("✓ GET /{id} - Récupérer transporteur par ID")
    void testGetCarrier() throws Exception {
        when(carrierService.findById(1L)).thenReturn(testCarrier1);

        mockMvc.perform(get("/api/carriers/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("FedEx"));

        verify(carrierService, times(1)).findById(1L);
    }

    @Test
    @DisplayName("✓ GET /{id} - Récupérer autre transporteur")
    void testGetCarrierAnother() throws Exception {
        when(carrierService.findById(2L)).thenReturn(testCarrier2);

        mockMvc.perform(get("/api/carriers/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("DHL"));

        verify(carrierService, times(1)).findById(2L);
    }


    @Test
    @DisplayName("✓ PUT /{id} - Mettre à jour un transporteur")
    void testUpdateCarrier() throws Exception {
        CarrierDTO updatedCarrier = CarrierDTO.builder()
                .name("FedEx Updated")
                .code("FDX")
                .status(CarrierStatus.ACTIVE)
                .build();

        when(carrierService.update(eq(1L), any(CarrierDTO.class)))
                .thenReturn(updatedCarrier);

        String requestBody = objectMapper.writeValueAsString(updatedCarrier);

        mockMvc.perform(put("/api/carriers/1")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("FedEx Updated"));

        verify(carrierService, times(1)).update(eq(1L), any(CarrierDTO.class));
    }

    @Test
    @DisplayName("❌ PUT /{id} - Erreur lors de la mise à jour")
    void testUpdateCarrierError() throws Exception {
        when(carrierService.update(eq(999L), any(CarrierDTO.class)))
                .thenThrow(new RuntimeException("Carrier not found"));

        String requestBody = objectMapper.writeValueAsString(testCarrier1);

        mockMvc.perform(put("/api/carriers/999")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isBadRequest());

        verify(carrierService, times(1)).update(eq(999L), any(CarrierDTO.class));
    }

    @Test
    @DisplayName("✓ PATCH /{id}/status - Mettre à jour le statut")
    void testUpdateCarrierStatus() throws Exception {
        CarrierDTO updatedStatus = CarrierDTO.builder()
                .name("FedEx")
                .status(CarrierStatus.INACTIVE)
                .build();

        when(carrierService.updateStatus(1L, "INACTIVE"))
                .thenReturn(updatedStatus);

        Map<String, String> statusRequest = new HashMap<>();
        statusRequest.put("status", "INACTIVE");

        String requestBody = objectMapper.writeValueAsString(statusRequest);

        mockMvc.perform(patch("/api/carriers/1/status")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("INACTIVE"));

        verify(carrierService, times(1)).updateStatus(1L, "INACTIVE");
    }

    @Test
    @DisplayName("✓ PATCH /{id}/status - Activer transporteur")
    void testUpdateCarrierStatusToActive() throws Exception {
        CarrierDTO activatedCarrier = CarrierDTO.builder()
                .name("FedEx")
                .status(CarrierStatus.INACTIVE)
                .build();

        when(carrierService.updateStatus(1L, "ACTIVE"))
                .thenReturn(activatedCarrier);

        Map<String, String> statusRequest = new HashMap<>();
        statusRequest.put("status", "ACTIVE");

        String requestBody = objectMapper.writeValueAsString(statusRequest);

        mockMvc.perform(patch("/api/carriers/1/status")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("FedEx"));

        verify(carrierService, times(1)).updateStatus(1L, "ACTIVE");
    }

    @Test
    @DisplayName("❌ PATCH /{id}/status - Erreur")
    void testUpdateCarrierStatusError() throws Exception {
        when(carrierService.updateStatus(999L, "INACTIVE"))
                .thenThrow(new RuntimeException("Carrier not found"));

        Map<String, String> statusRequest = new HashMap<>();
        statusRequest.put("status", "INACTIVE");

        String requestBody = objectMapper.writeValueAsString(statusRequest);

        mockMvc.perform(patch("/api/carriers/999/status")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isBadRequest());

        verify(carrierService, times(1)).updateStatus(999L, "INACTIVE");
    }



    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer un transporteur")
    void testDeleteCarrier() throws Exception {
        doNothing().when(carrierService).delete(1L);

        mockMvc.perform(delete("/api/carriers/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Carrier supprimé avec succès"));

        verify(carrierService, times(1)).delete(1L);
    }

    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer autre transporteur")
    void testDeleteCarrierAnother() throws Exception {
        doNothing().when(carrierService).delete(2L);

        mockMvc.perform(delete("/api/carriers/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Carrier supprimé avec succès"));

        verify(carrierService, times(1)).delete(2L);
    }

    @Test
    @DisplayName("❌ DELETE /{id} - Erreur lors de la suppression")
    void testDeleteCarrierError() throws Exception {
        doThrow(new RuntimeException("Carrier not found"))
                .when(carrierService).delete(999L);

        mockMvc.perform(delete("/api/carriers/999"))
                .andExpect(status().isBadRequest());

        verify(carrierService, times(1)).delete(999L);
    }
}