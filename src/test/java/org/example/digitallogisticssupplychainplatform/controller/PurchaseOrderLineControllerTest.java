package org.example.digitallogisticssupplychainplatform.controller;

import org.example.digitallogisticssupplychainplatform.dto.PurchaseOrderLineDTO;
import org.example.digitallogisticssupplychainplatform.service.PurchaseOrderLineService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - PurchaseOrderLineController")
class PurchaseOrderLineControllerTest {

    @Mock
    private PurchaseOrderLineService purchaseOrderLineService;

    private MockMvc mockMvc;

    private PurchaseOrderLineDTO testLineDTO1;
    private PurchaseOrderLineDTO testLineDTO2;
    private List<PurchaseOrderLineDTO> testLineList;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new PurchaseOrderLineController(purchaseOrderLineService)
        ).build();

        testLineDTO1 = PurchaseOrderLineDTO.builder()
                .id(1L)
                .productId(1L)
                .productName("Laptop")
                .quantity(50)
                .unitPrice(new BigDecimal("800.00"))
                .lineTotal(new BigDecimal("40000.00"))
                .build();

        testLineDTO2 = PurchaseOrderLineDTO.builder()
                .id(2L)
                .productId(2L)
                .productName("Monitor")
                .quantity(30)
                .unitPrice(new BigDecimal("300.00"))
                .lineTotal(new BigDecimal("9000.00"))
                .build();

        testLineList = new ArrayList<>();
        testLineList.add(testLineDTO1);
        testLineList.add(testLineDTO2);
    }



    @Test
    @DisplayName("✓ GET - Récupérer tous les lignes de commande")
    void testGetAllOrderLines() throws Exception {
        when(purchaseOrderLineService.getAllOrderLines()).thenReturn(testLineList);

        mockMvc.perform(get("/api/purchase-order-lines"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].productName").value("Laptop"))
                .andExpect(jsonPath("$[1].id").value(2))
                .andExpect(jsonPath("$[1].productName").value("Monitor"));

        verify(purchaseOrderLineService, times(1)).getAllOrderLines();
    }

    @Test
    @DisplayName("✓ GET - Récupérer tous les lignes - Liste vide")
    void testGetAllOrderLinesEmpty() throws Exception {
        when(purchaseOrderLineService.getAllOrderLines()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/purchase-order-lines"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(purchaseOrderLineService, times(1)).getAllOrderLines();
    }


    @Test
    @DisplayName("✓ GET /{id} - Récupérer une ligne par ID")
    void testGetOrderLineById() throws Exception {
        when(purchaseOrderLineService.getOrderLineById(1L)).thenReturn(testLineDTO1);

        mockMvc.perform(get("/api/purchase-order-lines/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.productName").value("Laptop"))
                .andExpect(jsonPath("$.quantity").value(50))
                .andExpect(jsonPath("$.unitPrice").value(800.00));

        verify(purchaseOrderLineService, times(1)).getOrderLineById(1L);
    }

    @Test
    @DisplayName("✓ GET /{id} - Récupérer avec ID valide")
    void testGetOrderLineByIdValid() throws Exception {
        when(purchaseOrderLineService.getOrderLineById(2L)).thenReturn(testLineDTO2);

        mockMvc.perform(get("/api/purchase-order-lines/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(2))
                .andExpect(jsonPath("$.productName").value("Monitor"));

        verify(purchaseOrderLineService, times(1)).getOrderLineById(2L);
    }



    @Test
    @DisplayName("✓ GET /purchase-order/{id} - Récupérer lignes par PO")
    void testGetOrderLinesByPurchaseOrder() throws Exception {
        when(purchaseOrderLineService.getOrderLinesByPurchaseOrder(1L)).thenReturn(testLineList);

        mockMvc.perform(get("/api/purchase-order-lines/purchase-order/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[1].id").value(2));

        verify(purchaseOrderLineService, times(1)).getOrderLinesByPurchaseOrder(1L);
    }

    @Test
    @DisplayName("✓ GET /purchase-order/{id} - PO sans lignes")
    void testGetOrderLinesByPurchaseOrderEmpty() throws Exception {
        when(purchaseOrderLineService.getOrderLinesByPurchaseOrder(999L)).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/purchase-order-lines/purchase-order/999"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(purchaseOrderLineService, times(1)).getOrderLinesByPurchaseOrder(999L);
    }


    @Test
    @DisplayName("✓ GET /product/{id} - Récupérer lignes par produit")
    void testGetOrderLinesByProduct() throws Exception {
        List<PurchaseOrderLineDTO> productLines = new ArrayList<>();
        productLines.add(testLineDTO1);
        when(purchaseOrderLineService.getOrderLinesByProduct(1L)).thenReturn(productLines);

        mockMvc.perform(get("/api/purchase-order-lines/product/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].productId").value(1))
                .andExpect(jsonPath("$[0].productName").value("Laptop"));

        verify(purchaseOrderLineService, times(1)).getOrderLinesByProduct(1L);
    }

    @Test
    @DisplayName("✓ GET /product/{id} - Produit sans lignes")
    void testGetOrderLinesByProductEmpty() throws Exception {
        when(purchaseOrderLineService.getOrderLinesByProduct(999L)).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/purchase-order-lines/product/999"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(purchaseOrderLineService, times(1)).getOrderLinesByProduct(999L);
    }



    @Test
    @DisplayName("✓ GET /product/{id}/pending - Récupérer lignes en attente")
    void testGetPendingOrderLinesByProduct() throws Exception {
        List<PurchaseOrderLineDTO> pendingLines = new ArrayList<>();
        pendingLines.add(testLineDTO1);
        when(purchaseOrderLineService.getPendingOrderLinesByProduct(1L)).thenReturn(pendingLines);

        mockMvc.perform(get("/api/purchase-order-lines/product/1/pending"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1));

        verify(purchaseOrderLineService, times(1)).getPendingOrderLinesByProduct(1L);
    }

    @Test
    @DisplayName("✓ GET /product/{id}/pending - Pas de lignes en attente")
    void testGetPendingOrderLinesByProductEmpty() throws Exception {
        when(purchaseOrderLineService.getPendingOrderLinesByProduct(999L)).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/purchase-order-lines/product/999/pending"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(purchaseOrderLineService, times(1)).getPendingOrderLinesByProduct(999L);
    }



    @Test
    @DisplayName("✓ GET /product/{id}/total-quantity - Récupérer quantité totale")
    void testGetTotalQuantityOrderedByProduct() throws Exception {
        when(purchaseOrderLineService.getTotalQuantityOrderedByProduct(1L)).thenReturn(50.0);

        mockMvc.perform(get("/api/purchase-order-lines/product/1/total-quantity"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value(50.0));

        verify(purchaseOrderLineService, times(1)).getTotalQuantityOrderedByProduct(1L);
    }

    @Test
    @DisplayName("✓ GET /product/{id}/total-quantity - Quantité zéro")
    void testGetTotalQuantityOrderedByProductZero() throws Exception {
        when(purchaseOrderLineService.getTotalQuantityOrderedByProduct(999L)).thenReturn(0.0);

        mockMvc.perform(get("/api/purchase-order-lines/product/999/total-quantity"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value(0.0));

        verify(purchaseOrderLineService, times(1)).getTotalQuantityOrderedByProduct(999L);
    }

    @Test
    @DisplayName("✓ GET /product/{id}/total-quantity - Quantité multiple")
    void testGetTotalQuantityOrderedByProductMultiple() throws Exception {
        when(purchaseOrderLineService.getTotalQuantityOrderedByProduct(1L)).thenReturn(150.0);

        mockMvc.perform(get("/api/purchase-order-lines/product/1/total-quantity"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value(150.0));

        verify(purchaseOrderLineService, times(1)).getTotalQuantityOrderedByProduct(1L);
    }



    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer une ligne")
    void testDeleteOrderLine() throws Exception {
        doNothing().when(purchaseOrderLineService).deleteOrderLine(1L);

        mockMvc.perform(delete("/api/purchase-order-lines/1"))
                .andExpect(status().isNoContent());

        verify(purchaseOrderLineService, times(1)).deleteOrderLine(1L);
    }

    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer une autre ligne")
    void testDeleteOrderLineAnother() throws Exception {
        doNothing().when(purchaseOrderLineService).deleteOrderLine(2L);

        mockMvc.perform(delete("/api/purchase-order-lines/2"))
                .andExpect(status().isNoContent());

        verify(purchaseOrderLineService, times(1)).deleteOrderLine(2L);
    }

    @Test
    @DisplayName("✓ DELETE /{id} - Supprimer avec ID valide")
    void testDeleteOrderLineValid() throws Exception {
        doNothing().when(purchaseOrderLineService).deleteOrderLine(anyLong());

        mockMvc.perform(delete("/api/purchase-order-lines/100"))
                .andExpect(status().isNoContent());

        verify(purchaseOrderLineService, times(1)).deleteOrderLine(100L);
    }
}