package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.*;
import org.example.digitallogisticssupplychainplatform.service.SalesOrderService;
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
@DisplayName("Tests - SalesOrderController")
class SalesOrderControllerTest {

    @Mock
    private SalesOrderService salesOrderService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private SalesOrderDTO testOrder1;
    private SalesOrderDTO testOrder2;
    private List<SalesOrderDTO> testOrders;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new SalesOrderController(salesOrderService)
        ).build();

        objectMapper = new ObjectMapper();

        testOrder1 = new SalesOrderDTO();
        testOrder1.setId(1L);

        testOrder1.setClientId(1L);

        testOrder1.setCreatedAt(LocalDateTime.now());

        testOrder2 = new SalesOrderDTO();
        testOrder2.setId(2L);

        testOrder2.setClientId(2L);

        testOrder2.setCreatedAt(LocalDateTime.now());

        testOrders = new ArrayList<>();
        testOrders.add(testOrder1);
        testOrders.add(testOrder2);
    }



    @Test
    @DisplayName("✓ GET / - Récupérer toutes les commandes")
    void testGetAllOrders() throws Exception {
        when(salesOrderService.findAll()).thenReturn(testOrders);

        mockMvc.perform(get("/api/sales-orders"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2));

        verify(salesOrderService, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ GET / - Liste vide")
    void testGetAllOrdersEmpty() throws Exception {
        when(salesOrderService.findAll()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/sales-orders"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(salesOrderService, times(1)).findAll();
    }



    @Test
    @DisplayName("✓ GET /{id} - Récupérer commande par ID")
    void testGetOrderById() throws Exception {
        when(salesOrderService.findById(1L)).thenReturn(testOrder1);

        mockMvc.perform(get("/api/sales-orders/1"))
                .andExpect(status().isOk());

        verify(salesOrderService, times(1)).findById(1L);
    }

    @Test
    @DisplayName("✓ GET /{id} - Récupérer autre commande")
    void testGetOrderByIdAnother() throws Exception {
        when(salesOrderService.findById(2L)).thenReturn(testOrder2);

        mockMvc.perform(get("/api/sales-orders/2"))
                .andExpect(status().isOk());

        verify(salesOrderService, times(1)).findById(2L);
    }


    @Test
    @DisplayName("✓ GET /client/{clientId} - Récupérer commandes par client")
    void testGetOrdersByClient() throws Exception {
        List<SalesOrderDTO> clientOrders = new ArrayList<>();
        clientOrders.add(testOrder1);

        when(salesOrderService.findByClientId(1L)).thenReturn(clientOrders);

        mockMvc.perform(get("/api/sales-orders/client/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1));

        verify(salesOrderService, times(1)).findByClientId(1L);
    }

    @Test
    @DisplayName("✓ GET /client/{clientId} - Commandes client 2")
    void testGetOrdersByClientAnother() throws Exception {
        List<SalesOrderDTO> clientOrders = new ArrayList<>();
        clientOrders.add(testOrder2);

        when(salesOrderService.findByClientId(2L)).thenReturn(clientOrders);

        mockMvc.perform(get("/api/sales-orders/client/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        verify(salesOrderService, times(1)).findByClientId(2L);
    }



    @Test
    @DisplayName("✓ POST / - Créer une commande")
    void testCreateOrder() throws Exception {
        SalesOrderCreateDTO createDTO = new SalesOrderCreateDTO();
        createDTO.setClientId(1L);

        List<SalesOrderLineCreateDTO> orderLines = new ArrayList<>();
        SalesOrderLineCreateDTO line1 = new SalesOrderLineCreateDTO();
        line1.setProductId(1L);
        line1.setQuantity(2);
        orderLines.add(line1);

        createDTO.setOrderLines(orderLines);

        when(salesOrderService.create(any(SalesOrderCreateDTO.class))).thenReturn(testOrder1);

        String requestBody = objectMapper.writeValueAsString(createDTO);

        mockMvc.perform(post("/api/sales-orders")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1L));

        verify(salesOrderService, times(1)).create(any(SalesOrderCreateDTO.class));
    }

    @Test
    @DisplayName("✓ POST / - Créer autre commande")
    void testCreateOrderAnother() throws Exception {
        SalesOrderCreateDTO createDTO = new SalesOrderCreateDTO();
        createDTO.setClientId(2L);

        List<SalesOrderLineCreateDTO> orderLines = new ArrayList<>();
        SalesOrderLineCreateDTO line1 = new SalesOrderLineCreateDTO();
        line1.setProductId(2L);
        line1.setQuantity(1);
        orderLines.add(line1);

        createDTO.setOrderLines(orderLines);

        when(salesOrderService.create(any(SalesOrderCreateDTO.class))).thenReturn(testOrder2);

        String requestBody = objectMapper.writeValueAsString(createDTO);

        mockMvc.perform(post("/api/sales-orders")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(2L));

        verify(salesOrderService, times(1)).create(any(SalesOrderCreateDTO.class));
    }


    @Test
    @DisplayName("✓ PUT /{id} - Mettre à jour une commande")
    void testUpdateOrder() throws Exception {
        SalesOrderUpdateDTO updateDTO = new SalesOrderUpdateDTO();


        SalesOrderDTO updatedOrder = new SalesOrderDTO();
        updatedOrder.setId(1L);


        when(salesOrderService.update(eq(1L), any(SalesOrderUpdateDTO.class)))
                .thenReturn(updatedOrder);

        String requestBody = objectMapper.writeValueAsString(updateDTO);

        mockMvc.perform(put("/api/sales-orders/1")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk());

        verify(salesOrderService, times(1)).update(eq(1L), any(SalesOrderUpdateDTO.class));
    }

    @Test
    @DisplayName("✓ PUT /{id} - Mettre à jour autre commande")
    void testUpdateOrderAnother() throws Exception {
        SalesOrderUpdateDTO updateDTO = new SalesOrderUpdateDTO();


        SalesOrderDTO updatedOrder = new SalesOrderDTO();
        updatedOrder.setId(2L);


        when(salesOrderService.update(eq(2L), any(SalesOrderUpdateDTO.class)))
                .thenReturn(updatedOrder);

        String requestBody = objectMapper.writeValueAsString(updateDTO);

        mockMvc.perform(put("/api/sales-orders/2")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk());

        verify(salesOrderService, times(1)).update(eq(2L), any(SalesOrderUpdateDTO.class));
    }



    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer une commande")
    void testDeleteOrder() throws Exception {
        doNothing().when(salesOrderService).delete(1L);

        mockMvc.perform(delete("/api/sales-orders/1"))
                .andExpect(status().isNoContent());

        verify(salesOrderService, times(1)).delete(1L);
    }

    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer autre commande")
    void testDeleteOrderAnother() throws Exception {
        doNothing().when(salesOrderService).delete(2L);

        mockMvc.perform(delete("/api/sales-orders/2"))
                .andExpect(status().isNoContent());

        verify(salesOrderService, times(1)).delete(2L);
    }
}