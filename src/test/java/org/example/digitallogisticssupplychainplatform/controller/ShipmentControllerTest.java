package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.ShipmentDTO;
import org.example.digitallogisticssupplychainplatform.dto.ShipmentUpdateDTO;
import org.example.digitallogisticssupplychainplatform.service.ShipmentService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
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
@DisplayName("Tests - ShipmentController")
class ShipmentControllerTest {

    @Mock
    private ShipmentService shipmentService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private ShipmentDTO testShipment1;
    private ShipmentDTO testShipment2;
    private List<ShipmentDTO> testShipments;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new ShipmentController(shipmentService)
        ).build();

        objectMapper = new ObjectMapper();

        testShipment1 = new ShipmentDTO();
        testShipment1.setId(1L);
        testShipment1.setTrackingNumber("TRACK-001");
        testShipment1.setCarrierId(1L);
        testShipment1.setStatus("PENDING");
        testShipment1.setDescription("Shipment 1");
        testShipment1.setPlannedDate(LocalDateTime.now());

        testShipment2 = new ShipmentDTO();
        testShipment2.setId(2L);
        testShipment2.setTrackingNumber("TRACK-002");
        testShipment2.setCarrierId(2L);
        testShipment2.setStatus("IN_TRANSIT");
        testShipment2.setDescription("Shipment 2");
        testShipment2.setPlannedDate(LocalDateTime.now());

        testShipments = new ArrayList<>();
        testShipments.add(testShipment1);
        testShipments.add(testShipment2);
    }



    @Test
    @DisplayName("✓ GET / - Récupérer tous les expéditions")
    void testGetAllShipments() throws Exception {
        when(shipmentService.findAll()).thenReturn(testShipments);

        mockMvc.perform(get("/api/shipments"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2));

        verify(shipmentService, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ GET / - Liste vide")
    void testGetAllShipmentsEmpty() throws Exception {
        when(shipmentService.findAll()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/shipments"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(shipmentService, times(1)).findAll();
    }



    @Test
    @DisplayName("✓ GET /{id} - Récupérer expédition par ID")
    void testGetShipmentById() throws Exception {
        when(shipmentService.findById(1L)).thenReturn(testShipment1);

        mockMvc.perform(get("/api/shipments/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trackingNumber").value("TRACK-001"));

        verify(shipmentService, times(1)).findById(1L);
    }

    @Test
    @DisplayName("✓ GET /{id} - Récupérer autre expédition")
    void testGetShipmentByIdAnother() throws Exception {
        when(shipmentService.findById(2L)).thenReturn(testShipment2);

        mockMvc.perform(get("/api/shipments/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trackingNumber").value("TRACK-002"));

        verify(shipmentService, times(1)).findById(2L);
    }



    @Test
    @DisplayName("✓ GET /tracking/{trackingNumber} - Récupérer par tracking number")
    void testGetShipmentByTracking() throws Exception {
        when(shipmentService.findByTrackingNumber("TRACK-001")).thenReturn(testShipment1);

        mockMvc.perform(get("/api/shipments/tracking/TRACK-001"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trackingNumber").value("TRACK-001"));

        verify(shipmentService, times(1)).findByTrackingNumber("TRACK-001");
    }



    @Test
    @DisplayName("✓ GET /carrier/{carrierId} - Récupérer expéditions par transporteur")
    void testGetShipmentsByCarrier() throws Exception {
        List<ShipmentDTO> carrierShipments = new ArrayList<>();
        carrierShipments.add(testShipment1);

        when(shipmentService.findByCarrierId(1L)).thenReturn(carrierShipments);

        mockMvc.perform(get("/api/shipments/carrier/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1));

        verify(shipmentService, times(1)).findByCarrierId(1L);
    }



    @Test
    @DisplayName("✓ GET /status/{status} - Récupérer expéditions par statut")
    void testGetShipmentsByStatus() throws Exception {
        List<ShipmentDTO> pendingShipments = new ArrayList<>();
        pendingShipments.add(testShipment1);

        when(shipmentService.findByStatus("PENDING")).thenReturn(pendingShipments);

        mockMvc.perform(get("/api/shipments/status/PENDING"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1));

        verify(shipmentService, times(1)).findByStatus("PENDING");
    }

    @Test
    @DisplayName("✓ GET /status/{status} - Statut IN_TRANSIT")
    void testGetShipmentsByStatusInTransit() throws Exception {
        List<ShipmentDTO> inTransitShipments = new ArrayList<>();
        inTransitShipments.add(testShipment2);

        when(shipmentService.findByStatus("IN_TRANSIT")).thenReturn(inTransitShipments);

        mockMvc.perform(get("/api/shipments/status/IN_TRANSIT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        verify(shipmentService, times(1)).findByStatus("IN_TRANSIT");
    }




    @Test
    @DisplayName("✓ PUT /{id} - Mettre à jour une expédition")
    void testUpdateShipment() throws Exception {
        ShipmentUpdateDTO updateDTO = new ShipmentUpdateDTO();
        updateDTO.setStatus("IN_TRANSIT");
        updateDTO.setDescription("Updated shipment");

        ShipmentDTO updatedShipment = new ShipmentDTO();
        updatedShipment.setId(1L);
        updatedShipment.setTrackingNumber("TRACK-001");
        updatedShipment.setStatus("IN_TRANSIT");

        when(shipmentService.update(eq(1L), any(ShipmentUpdateDTO.class)))
                .thenReturn(updatedShipment);

        String requestBody = objectMapper.writeValueAsString(updateDTO);

        mockMvc.perform(put("/api/shipments/1")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk());

        verify(shipmentService, times(1)).update(eq(1L), any(ShipmentUpdateDTO.class));
    }

    @Test
    @DisplayName("✓ PUT /{id} - Mettre à jour autre expédition")
    void testUpdateShipmentAnother() throws Exception {
        ShipmentUpdateDTO updateDTO = new ShipmentUpdateDTO();
        updateDTO.setStatus("DELIVERED");

        ShipmentDTO updatedShipment = new ShipmentDTO();
        updatedShipment.setId(2L);
        updatedShipment.setTrackingNumber("TRACK-002");
        updatedShipment.setStatus("DELIVERED");

        when(shipmentService.update(eq(2L), any(ShipmentUpdateDTO.class)))
                .thenReturn(updatedShipment);

        String requestBody = objectMapper.writeValueAsString(updateDTO);

        mockMvc.perform(put("/api/shipments/2")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk());

        verify(shipmentService, times(1)).update(eq(2L), any(ShipmentUpdateDTO.class));
    }



    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer une expédition")
    void testDeleteShipment() throws Exception {
        doNothing().when(shipmentService).delete(1L);

        mockMvc.perform(delete("/api/shipments/1"))
                .andExpect(status().isNoContent());

        verify(shipmentService, times(1)).delete(1L);
    }

    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer autre expédition")
    void testDeleteShipmentAnother() throws Exception {
        doNothing().when(shipmentService).delete(2L);

        mockMvc.perform(delete("/api/shipments/2"))
                .andExpect(status().isNoContent());

        verify(shipmentService, times(1)).delete(2L);
    }
}