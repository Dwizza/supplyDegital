package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.service.SalesOrderBusinessService;
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
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - SalesOrderBusinessController")
class SalesOrderBusinessControllerTest {

    @Mock
    private SalesOrderBusinessService salesOrderBusinessService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private SalesOrderBusinessService.ReservationResult reservationResult;
    private SalesOrderBusinessService.AvailabilityCheck availabilityCheck;
    private SalesOrderBusinessService.ShipmentResult shipmentResult;
    private SalesOrderBusinessService.CancellationResult cancellationResult;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new SalesOrderBusinessController(salesOrderBusinessService)
        ).build();

        objectMapper = new ObjectMapper();

        reservationResult = SalesOrderBusinessService.ReservationResult.builder()
                .orderId(1L)
                .fullyReserved(true)
                .reservedAt(LocalDateTime.now())
                .build();


        availabilityCheck = SalesOrderBusinessService.AvailabilityCheck.builder()
                .orderId(1L)
                .canReserveCompletely(true)
                .products(new ArrayList<>())
                .build();


        shipmentResult = SalesOrderBusinessService.ShipmentResult.builder()
                .orderId(1L)
                .shippedAt(LocalDateTime.now())
                .movements(new ArrayList<>())
                .build();
        cancellationResult = SalesOrderBusinessService.CancellationResult.builder()
                .orderId(1L)
                .reason("Test cancellation")
                .cancelledAt(LocalDateTime.now())
                .build();
    }



    @Test
    @DisplayName("✓ POST /reserve - Réserver une commande complètement")
    void testReserveOrder() throws Exception {
        when(salesOrderBusinessService.reserveOrder(1L, 1L)).thenReturn(reservationResult);

        mockMvc.perform(post("/api/sales-orders/business/1/reserve")
                        .param("warehouseId", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orderId").value(1))
                .andExpect(jsonPath("$.fullyReserved").value(true));

        verify(salesOrderBusinessService, times(1)).reserveOrder(1L, 1L);
    }

    @Test
    @DisplayName("✓ POST /reserve - Réserver autre commande")
    void testReserveOrderAnother() throws Exception {
        when(salesOrderBusinessService.reserveOrder(2L, 2L)).thenReturn(reservationResult);

        mockMvc.perform(post("/api/sales-orders/business/2/reserve")
                        .param("warehouseId", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orderId").value(1));

        verify(salesOrderBusinessService, times(1)).reserveOrder(2L, 2L);
    }


    @Test
    @DisplayName("✓ GET /check - Vérifier la disponibilité")
    void testCheckAvailability() throws Exception {
        when(salesOrderBusinessService.checkAvailability(1L, 1L)).thenReturn(availabilityCheck);

        mockMvc.perform(get("/api/sales-orders/business/1/check")
                        .param("warehouseId", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orderId").value(1))
                .andExpect(jsonPath("$.canReserveCompletely").value(true));

        verify(salesOrderBusinessService, times(1)).checkAvailability(1L, 1L);
    }

    @Test
    @DisplayName("✓ GET /check - Vérifier autre commande")
    void testCheckAvailabilityAnother() throws Exception {
        when(salesOrderBusinessService.checkAvailability(2L, 2L)).thenReturn(availabilityCheck);

        mockMvc.perform(get("/api/sales-orders/business/2/check")
                        .param("warehouseId", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.canReserveCompletely").value(true));

        verify(salesOrderBusinessService, times(1)).checkAvailability(2L, 2L);
    }


    @Test
    @DisplayName("✓ POST /ship - Expédier une commande")
    void testShipOrder() throws Exception {
        when(salesOrderBusinessService.shipOrder(1L, 1L)).thenReturn(shipmentResult);

        mockMvc.perform(post("/api/sales-orders/business/1/ship")
                        .param("warehouseId", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orderId").value(1));

        verify(salesOrderBusinessService, times(1)).shipOrder(1L, 1L);
    }

    @Test
    @DisplayName("✓ POST /ship - Expédier autre commande")
    void testShipOrderAnother() throws Exception {
        when(salesOrderBusinessService.shipOrder(2L, 2L)).thenReturn(shipmentResult);

        mockMvc.perform(post("/api/sales-orders/business/2/ship")
                        .param("warehouseId", "2"))
                .andExpect(status().isOk());

        verify(salesOrderBusinessService, times(1)).shipOrder(2L, 2L);
    }


    @Test
    @DisplayName("✓ POST /deliver - Livrer une commande")
    void testDeliverOrder() throws Exception {
        doNothing().when(salesOrderBusinessService).deliverOrder(1L);

        mockMvc.perform(post("/api/sales-orders/business/1/deliver"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orderId").value(1))
                .andExpect(jsonPath("$.message").value("✓ Commande livrée avec succès"));

        verify(salesOrderBusinessService, times(1)).deliverOrder(1L);
    }

    @Test
    @DisplayName("✓ POST /deliver - Livrer autre commande")
    void testDeliverOrderAnother() throws Exception {
        doNothing().when(salesOrderBusinessService).deliverOrder(2L);

        mockMvc.perform(post("/api/sales-orders/business/2/deliver"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orderId").value(2));

        verify(salesOrderBusinessService, times(1)).deliverOrder(2L);
    }


    @Test
    @DisplayName("✓ POST /cancel - Annuler une commande")
    void testCancelOrder() throws Exception {
        when(salesOrderBusinessService.cancelOrder(1L, "Client request", 1L))
                .thenReturn(cancellationResult);

        SalesOrderBusinessController.CancelRequest request =
                new SalesOrderBusinessController.CancelRequest("Client request");

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/sales-orders/business/1/cancel")
                        .param("warehouseId", "1")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orderId").value(1))
                .andExpect(jsonPath("$.reason").value("Test cancellation"));

        verify(salesOrderBusinessService, times(1)).cancelOrder(1L, "Client request", 1L);
    }

    @Test
    @DisplayName("✓ POST /cancel - Annuler autre commande")
    void testCancelOrderAnother() throws Exception {
        when(salesOrderBusinessService.cancelOrder(2L, "Out of stock", 2L))
                .thenReturn(cancellationResult);

        SalesOrderBusinessController.CancelRequest request =
                new SalesOrderBusinessController.CancelRequest("Out of stock");

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/sales-orders/business/2/cancel")
                        .param("warehouseId", "2")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk());

        verify(salesOrderBusinessService, times(1)).cancelOrder(2L, "Out of stock", 2L);
    }

    @Test
    @DisplayName("POST /cancel - Raison manquante")
    void testCancelOrderNoReason() throws Exception {
        String requestBody = "{\"reason\": \"\"}";

        mockMvc.perform(post("/api/sales-orders/business/1/cancel")
                        .param("warehouseId", "1")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isBadRequest());

        verify(salesOrderBusinessService, never()).cancelOrder(anyLong(), anyString(), anyLong());
    }


}