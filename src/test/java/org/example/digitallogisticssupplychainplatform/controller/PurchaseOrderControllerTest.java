package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.CreatePurchaseOrderRequest;
import org.example.digitallogisticssupplychainplatform.dto.PurchaseOrderDTO;
import org.example.digitallogisticssupplychainplatform.dto.UpdatePurchaseOrderStatusRequest;
import org.example.digitallogisticssupplychainplatform.service.PurchaseOrderService;
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
@DisplayName("Tests - PurchaseOrderController")
class PurchaseOrderControllerTest {

    @Mock
    private PurchaseOrderService purchaseOrderService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private PurchaseOrderDTO testOrder1;
    private PurchaseOrderDTO testOrder2;
    private List<PurchaseOrderDTO> testOrders;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new PurchaseOrderController(purchaseOrderService)
        ).build();

        objectMapper = new ObjectMapper();

        testOrder1 = new PurchaseOrderDTO();
        testOrder1.setId(1L);
        testOrder1.setSupplierId(1L);
        testOrder1.setWarehouseManagerId(1L);
        testOrder1.setStatus("DRAFT");
        testOrder1.setCreatedAt(LocalDateTime.now());

        testOrder2 = new PurchaseOrderDTO();
        testOrder2.setId(2L);
        testOrder2.setSupplierId(2L);
        testOrder2.setWarehouseManagerId(2L);
        testOrder2.setStatus("CONFIRMED");
        testOrder2.setCreatedAt(LocalDateTime.now());

        testOrders = new ArrayList<>();
        testOrders.add(testOrder1);
        testOrders.add(testOrder2);
    }



    @Test
    @DisplayName("✓ POST / - Créer une commande d'achat")
    void testCreatePurchaseOrder() throws Exception {
        CreatePurchaseOrderRequest request = new CreatePurchaseOrderRequest();
        request.setSupplierId(1L);
        request.setWarehouseManagerId(1L);

        when(purchaseOrderService.createPurchaseOrder(any(CreatePurchaseOrderRequest.class)))
                .thenReturn(testOrder1);

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/purchase-orders")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk());

        verify(purchaseOrderService, times(1)).createPurchaseOrder(any(CreatePurchaseOrderRequest.class));
    }

    @Test
    @DisplayName("✓ POST / - Créer autre commande d'achat")
    void testCreatePurchaseOrderAnother() throws Exception {
        CreatePurchaseOrderRequest request = new CreatePurchaseOrderRequest();
        request.setSupplierId(2L);
        request.setWarehouseManagerId(2L);

        when(purchaseOrderService.createPurchaseOrder(any(CreatePurchaseOrderRequest.class)))
                .thenReturn(testOrder2);

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/purchase-orders")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk());

        verify(purchaseOrderService, times(1)).createPurchaseOrder(any(CreatePurchaseOrderRequest.class));
    }



    @Test
    @DisplayName("✓ GET / - Récupérer toutes les commandes d'achat")
    void testGetAllPurchaseOrders() throws Exception {
        when(purchaseOrderService.getAllPurchaseOrders()).thenReturn(testOrders);

        mockMvc.perform(get("/api/purchase-orders"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2));

        verify(purchaseOrderService, times(1)).getAllPurchaseOrders();
    }

    @Test
    @DisplayName("✓ GET / - Liste vide")
    void testGetAllPurchaseOrdersEmpty() throws Exception {
        when(purchaseOrderService.getAllPurchaseOrders()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/purchase-orders"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(purchaseOrderService, times(1)).getAllPurchaseOrders();
    }



    @Test
    @DisplayName("✓ GET /{id} - Récupérer commande d'achat par ID")
    void testGetPurchaseOrderById() throws Exception {
        when(purchaseOrderService.getPurchaseOrderById(1L)).thenReturn(testOrder1);

        mockMvc.perform(get("/api/purchase-orders/1"))
                .andExpect(status().isOk());

        verify(purchaseOrderService, times(1)).getPurchaseOrderById(1L);
    }

    @Test
    @DisplayName("✓ GET /{id} - Récupérer autre commande d'achat")
    void testGetPurchaseOrderByIdAnother() throws Exception {
        when(purchaseOrderService.getPurchaseOrderById(2L)).thenReturn(testOrder2);

        mockMvc.perform(get("/api/purchase-orders/2"))
                .andExpect(status().isOk());

        verify(purchaseOrderService, times(1)).getPurchaseOrderById(2L);
    }


    @Test
    @DisplayName("✓ PUT /{id}/status - Mettre à jour le statut")
    void testUpdatePurchaseOrderStatus() throws Exception {
        UpdatePurchaseOrderStatusRequest request = new UpdatePurchaseOrderStatusRequest();
        request.setStatus("CONFIRMED");

        PurchaseOrderDTO updatedOrder = new PurchaseOrderDTO();
        updatedOrder.setId(1L);
        updatedOrder.setStatus("CONFIRMED");

        when(purchaseOrderService.updatePurchaseOrderStatus(eq(1L), any(UpdatePurchaseOrderStatusRequest.class)))
                .thenReturn(updatedOrder);

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(put("/api/purchase-orders/1/status")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk());

        verify(purchaseOrderService, times(1))
                .updatePurchaseOrderStatus(eq(1L), any(UpdatePurchaseOrderStatusRequest.class));
    }

    @Test
    @DisplayName("✓ PUT /{id}/status - Mettre à jour autre statut")
    void testUpdatePurchaseOrderStatusAnother() throws Exception {
        UpdatePurchaseOrderStatusRequest request = new UpdatePurchaseOrderStatusRequest();
        request.setStatus("RECEIVED");

        PurchaseOrderDTO updatedOrder = new PurchaseOrderDTO();
        updatedOrder.setId(2L);
        updatedOrder.setStatus("RECEIVED");

        when(purchaseOrderService.updatePurchaseOrderStatus(eq(2L), any(UpdatePurchaseOrderStatusRequest.class)))
                .thenReturn(updatedOrder);

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(put("/api/purchase-orders/2/status")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk());

        verify(purchaseOrderService, times(1))
                .updatePurchaseOrderStatus(eq(2L), any(UpdatePurchaseOrderStatusRequest.class));
    }



    @Test
    @DisplayName("✓ GET /status/{status} - Récupérer par statut DRAFT")
    void testGetPurchaseOrdersByStatus() throws Exception {
        List<PurchaseOrderDTO> draftOrders = new ArrayList<>();
        draftOrders.add(testOrder1);

        when(purchaseOrderService.getPurchaseOrdersByStatus("DRAFT")).thenReturn(draftOrders);

        mockMvc.perform(get("/api/purchase-orders/status/DRAFT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        verify(purchaseOrderService, times(1)).getPurchaseOrdersByStatus("DRAFT");
    }

    @Test
    @DisplayName("✓ GET /status/{status} - Récupérer par statut CONFIRMED")
    void testGetPurchaseOrdersByStatusConfirmed() throws Exception {
        List<PurchaseOrderDTO> confirmedOrders = new ArrayList<>();
        confirmedOrders.add(testOrder2);

        when(purchaseOrderService.getPurchaseOrdersByStatus("CONFIRMED")).thenReturn(confirmedOrders);

        mockMvc.perform(get("/api/purchase-orders/status/CONFIRMED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        verify(purchaseOrderService, times(1)).getPurchaseOrdersByStatus("CONFIRMED");
    }



    @Test
    @DisplayName("✓ GET /supplier/{supplierId} - Récupérer par fournisseur")
    void testGetPurchaseOrdersBySupplier() throws Exception {
        List<PurchaseOrderDTO> supplierOrders = new ArrayList<>();
        supplierOrders.add(testOrder1);

        when(purchaseOrderService.getPurchaseOrdersBySupplier(1L)).thenReturn(supplierOrders);

        mockMvc.perform(get("/api/purchase-orders/supplier/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        verify(purchaseOrderService, times(1)).getPurchaseOrdersBySupplier(1L);
    }

    @Test
    @DisplayName("✓ GET /supplier/{supplierId} - Récupérer par autre fournisseur")
    void testGetPurchaseOrdersBySupplierAnother() throws Exception {
        List<PurchaseOrderDTO> supplierOrders = new ArrayList<>();
        supplierOrders.add(testOrder2);

        when(purchaseOrderService.getPurchaseOrdersBySupplier(2L)).thenReturn(supplierOrders);

        mockMvc.perform(get("/api/purchase-orders/supplier/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        verify(purchaseOrderService, times(1)).getPurchaseOrdersBySupplier(2L);
    }


    @Test
    @DisplayName("✓ GET /warehouse-manager/{warehouseManagerId} - Récupérer par manager")
    void testGetPurchaseOrdersByWarehouseManager() throws Exception {
        List<PurchaseOrderDTO> managerOrders = new ArrayList<>();
        managerOrders.add(testOrder1);

        when(purchaseOrderService.getPurchaseOrdersByWarehouseManager(1L)).thenReturn(managerOrders);

        mockMvc.perform(get("/api/purchase-orders/warehouse-manager/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        verify(purchaseOrderService, times(1)).getPurchaseOrdersByWarehouseManager(1L);
    }

    @Test
    @DisplayName("✓ GET /warehouse-manager/{warehouseManagerId} - Récupérer par autre manager")
    void testGetPurchaseOrdersByWarehouseManagerAnother() throws Exception {
        List<PurchaseOrderDTO> managerOrders = new ArrayList<>();
        managerOrders.add(testOrder2);

        when(purchaseOrderService.getPurchaseOrdersByWarehouseManager(2L)).thenReturn(managerOrders);

        mockMvc.perform(get("/api/purchase-orders/warehouse-manager/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        verify(purchaseOrderService, times(1)).getPurchaseOrdersByWarehouseManager(2L);
    }



    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer une commande d'achat")
    void testDeletePurchaseOrder() throws Exception {
        doNothing().when(purchaseOrderService).deletePurchaseOrder(1L);

        mockMvc.perform(delete("/api/purchase-orders/1"))
                .andExpect(status().isNoContent());

        verify(purchaseOrderService, times(1)).deletePurchaseOrder(1L);
    }

    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer autre commande d'achat")
    void testDeletePurchaseOrderAnother() throws Exception {
        doNothing().when(purchaseOrderService).deletePurchaseOrder(2L);

        mockMvc.perform(delete("/api/purchase-orders/2"))
                .andExpect(status().isNoContent());

        verify(purchaseOrderService, times(1)).deletePurchaseOrder(2L);
    }
}