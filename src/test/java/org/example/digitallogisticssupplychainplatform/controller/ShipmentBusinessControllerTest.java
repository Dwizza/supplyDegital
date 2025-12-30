package org.example.digitallogisticssupplychainplatform.controller;

import org.example.digitallogisticssupplychainplatform.entity.ShipmentStatus;
import org.example.digitallogisticssupplychainplatform.service.ShipmentBusinessService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - ShipmentBusinessController")
class ShipmentBusinessControllerTest {

    @Mock
    private ShipmentBusinessService shipmentBusinessService;

    private MockMvc mockMvc;

    private ShipmentBusinessService.ShipmentTracking testTracking;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new ShipmentBusinessController(shipmentBusinessService)
        ).build();

        testTracking = ShipmentBusinessService.ShipmentTracking.builder()
                .trackingNumber("TRACK-001")
                .build();
    }


    @Test
    @DisplayName("✓ GET /track - Suivre une expédition")
    void testTrackShipment() throws Exception {
        when(shipmentBusinessService.trackShipment("TRACK-001")).thenReturn(testTracking);

        mockMvc.perform(get("/api/shipments/business/track/TRACK-001"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trackingNumber").value("TRACK-001"));

        verify(shipmentBusinessService, times(1)).trackShipment("TRACK-001");
    }

    @Test
    @DisplayName("✓ GET /track - Suivre autre expédition")
    void testTrackShipmentAnother() throws Exception {
        ShipmentBusinessService.ShipmentTracking tracking2 =
                ShipmentBusinessService.ShipmentTracking.builder()
                        .trackingNumber("TRACK-002")

                        .build();

        when(shipmentBusinessService.trackShipment("TRACK-002")).thenReturn(tracking2);

        mockMvc.perform(get("/api/shipments/business/track/TRACK-002"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trackingNumber").value("TRACK-002"));

        verify(shipmentBusinessService, times(1)).trackShipment("TRACK-002");
    }

    @Test
    @DisplayName("✓ GET /track - Expédition en attente")
    void testTrackShipmentPending() throws Exception {
        ShipmentBusinessService.ShipmentTracking pendingTracking =
                ShipmentBusinessService.ShipmentTracking.builder()
                        .trackingNumber("TRACK-003")

                        .build();

        when(shipmentBusinessService.trackShipment("TRACK-003")).thenReturn(pendingTracking);

        mockMvc.perform(get("/api/shipments/business/track/TRACK-003"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trackingNumber").value("TRACK-003"));

        verify(shipmentBusinessService, times(1)).trackShipment("TRACK-003");
    }


    @Test
    @DisplayName("✓ POST /start-transit - Démarrer le transit")
    void testStartTransit() throws Exception {
        doNothing().when(shipmentBusinessService)
                .updateStatus(1L, ShipmentStatus.IN_TRANSIT);

        mockMvc.perform(post("/api/shipments/business/1/start-transit"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.shipmentId").value(1))
                .andExpect(jsonPath("$.newStatus").value("IN_TRANSIT"))
                .andExpect(jsonPath("$.message").value("Expédition en transit"));

        verify(shipmentBusinessService, times(1))
                .updateStatus(1L, ShipmentStatus.IN_TRANSIT);
    }

    @Test
    @DisplayName("✓ POST /start-transit - Démarrer autre transit")
    void testStartTransitAnother() throws Exception {
        doNothing().when(shipmentBusinessService)
                .updateStatus(2L, ShipmentStatus.IN_TRANSIT);

        mockMvc.perform(post("/api/shipments/business/2/start-transit"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.shipmentId").value(2))
                .andExpect(jsonPath("$.newStatus").value("IN_TRANSIT"));

        verify(shipmentBusinessService, times(1))
                .updateStatus(2L, ShipmentStatus.IN_TRANSIT);
    }

    @Test
    @DisplayName("✓ POST /start-transit - Multiple shipments")
    void testStartTransitMultiple() throws Exception {
        doNothing().when(shipmentBusinessService)
                .updateStatus(anyLong(), eq(ShipmentStatus.IN_TRANSIT));

        mockMvc.perform(post("/api/shipments/business/3/start-transit"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/shipments/business/4/start-transit"))
                .andExpect(status().isOk());

        verify(shipmentBusinessService, times(2))
                .updateStatus(anyLong(), eq(ShipmentStatus.IN_TRANSIT));
    }


    @Test
    @DisplayName("✓ POST /deliver - Livrer une expédition")
    void testDeliver() throws Exception {
        doNothing().when(shipmentBusinessService)
                .updateStatus(1L, ShipmentStatus.DELIVERED);

        mockMvc.perform(post("/api/shipments/business/1/deliver"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.shipmentId").value(1))
                .andExpect(jsonPath("$.newStatus").value("DELIVERED"))
                .andExpect(jsonPath("$.message").value(" Expédition livrée"));

        verify(shipmentBusinessService, times(1))
                .updateStatus(1L, ShipmentStatus.DELIVERED);
    }

    @Test
    @DisplayName("✓ POST /deliver - Livrer autre expédition")
    void testDeliverAnother() throws Exception {
        doNothing().when(shipmentBusinessService)
                .updateStatus(2L, ShipmentStatus.DELIVERED);

        mockMvc.perform(post("/api/shipments/business/2/deliver"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.shipmentId").value(2))
                .andExpect(jsonPath("$.newStatus").value("DELIVERED"));

        verify(shipmentBusinessService, times(1))
                .updateStatus(2L, ShipmentStatus.DELIVERED);
    }

    @Test
    @DisplayName("✓ POST /deliver - Livrer plusieurs expéditions")
    void testDeliverMultiple() throws Exception {
        doNothing().when(shipmentBusinessService)
                .updateStatus(anyLong(), eq(ShipmentStatus.DELIVERED));

        mockMvc.perform(post("/api/shipments/business/1/deliver"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/shipments/business/2/deliver"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/shipments/business/3/deliver"))
                .andExpect(status().isOk());

        verify(shipmentBusinessService, times(3))
                .updateStatus(anyLong(), eq(ShipmentStatus.DELIVERED));
    }


    @Test
    @DisplayName("✓ POST /start-transit + /deliver - Cycle complet")
    void testShipmentCompleteLifecycle() throws Exception {
        doNothing().when(shipmentBusinessService).updateStatus(anyLong(), any(ShipmentStatus.class));


        mockMvc.perform(post("/api/shipments/business/1/start-transit"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.newStatus").value("IN_TRANSIT"));

        mockMvc.perform(post("/api/shipments/business/1/deliver"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.newStatus").value("DELIVERED"));

        verify(shipmentBusinessService, times(1))
                .updateStatus(1L, ShipmentStatus.IN_TRANSIT);
        verify(shipmentBusinessService, times(1))
                .updateStatus(1L, ShipmentStatus.DELIVERED);
    }

    @Test
    @DisplayName("✓ GET /track - Vérifier le statut après livraison")
    void testTrackAfterDelivery() throws Exception {
        ShipmentBusinessService.ShipmentTracking deliveredTracking =
                ShipmentBusinessService.ShipmentTracking.builder()
                        .trackingNumber("TRACK-004")

                        .build();

        when(shipmentBusinessService.trackShipment("TRACK-004")).thenReturn(deliveredTracking);

        mockMvc.perform(get("/api/shipments/business/track/TRACK-004"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trackingNumber").value("TRACK-004"));

        verify(shipmentBusinessService, times(1)).trackShipment("TRACK-004");
    }
}