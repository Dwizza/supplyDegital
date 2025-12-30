package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.service.InventoryBusinessService;
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
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - InventoryBusinessController")
class InventoryBusinessControllerTest {

    @Mock
    private InventoryBusinessService inventoryBusinessService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private InventoryMovementDTO testMovement;
    private List<InventoryBusinessService.AllocationResult> testAllocations;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new InventoryBusinessController(inventoryBusinessService)
        ).build();

        objectMapper = new ObjectMapper();

        testMovement = InventoryMovementDTO.builder()
                .id(1L)
                .inventoryId(1L)
                .warehouseId(1L)
                .productId(1L)
                .quantity(50)
                .referenceDoc("PO-001")
                .description("Stock inbound")
                .build();

        testAllocations = new ArrayList<>();
        testAllocations.add(InventoryBusinessService.AllocationResult.builder()
                .warehouseId(1L)
                .allocatedQuantity(30)
                .build());
        testAllocations.add(InventoryBusinessService.AllocationResult.builder()
                .warehouseId(2L)
                .allocatedQuantity(20)
                .build());
    }

    // ============================================================
    // TEST: GET /api/inventory/operations/{inventoryId}/available
    // ============================================================

    @Test
    @DisplayName("✓ GET /available - Récupérer quantité disponible")
    void testGetAvailableQuantity() throws Exception {
        when(inventoryBusinessService.calculateAvailableQty(1L)).thenReturn(100);

        mockMvc.perform(get("/api/inventory/operations/1/available"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.inventoryId").value(1))
                .andExpect(jsonPath("$.availableQuantity").value(100));

        verify(inventoryBusinessService, times(1)).calculateAvailableQty(1L);
    }

    @Test
    @DisplayName("✓ GET /available - Quantité zéro")
    void testGetAvailableQuantityZero() throws Exception {
        when(inventoryBusinessService.calculateAvailableQty(2L)).thenReturn(0);

        mockMvc.perform(get("/api/inventory/operations/2/available"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.availableQuantity").value(0));

        verify(inventoryBusinessService, times(1)).calculateAvailableQty(2L);
    }

    // ============================================================
    // TEST: POST /api/inventory/operations/reserve
    // ============================================================

    @Test
    @DisplayName("✓ POST /reserve - Réserver du stock")
    void testReserveStock() throws Exception {
        doNothing().when(inventoryBusinessService).reserveStock(1L, 1L, 10, "SO-001");

        InventoryBusinessController.ReservationRequest request =
                InventoryBusinessController.ReservationRequest.builder()
                        .productId(1L)
                        .warehouseId(1L)
                        .quantity(10)
                        .referenceDoc("SO-001")
                        .build();

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/inventory/operations/reserve")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Stock réservé avec succès"))
                .andExpect(jsonPath("$.quantityReserved").value(10));

        verify(inventoryBusinessService, times(1)).reserveStock(1L, 1L, 10, "SO-001");
    }

    @Test
    @DisplayName("✓ POST /reserve - Réserver avec quantité valide")
    void testReserveStockValid() throws Exception {
        doNothing().when(inventoryBusinessService).reserveStock(2L, 2L, 50, "SO-002");

        InventoryBusinessController.ReservationRequest request =
                InventoryBusinessController.ReservationRequest.builder()
                        .productId(2L)
                        .warehouseId(2L)
                        .quantity(50)
                        .referenceDoc("SO-002")
                        .build();

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/inventory/operations/reserve")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        verify(inventoryBusinessService, times(1)).reserveStock(2L, 2L, 50, "SO-002");
    }

    // ============================================================
    // TEST: POST /api/inventory/operations/release
    // ============================================================

    @Test
    @DisplayName("✓ POST /release - Libérer une réservation")
    void testReleaseReservation() throws Exception {
        doNothing().when(inventoryBusinessService).releaseReservation(1L, 1L, 10, "SO-001");

        InventoryBusinessController.ReservationRequest request =
                InventoryBusinessController.ReservationRequest.builder()
                        .productId(1L)
                        .warehouseId(1L)
                        .quantity(10)
                        .referenceDoc("SO-001")
                        .build();

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/inventory/operations/release")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Réservation libérée avec succès"));

        verify(inventoryBusinessService, times(1)).releaseReservation(1L, 1L, 10, "SO-001");
    }

    // ============================================================
    // TEST: POST /api/inventory/operations/inbound
    // ============================================================

    @Test
    @DisplayName("✓ POST /inbound - Enregistrer entrée de stock")
    void testRecordInbound() throws Exception {
        when(inventoryBusinessService.recordInbound(1L, 1L, 50, "PO-001", "Stock inbound"))
                .thenReturn(testMovement);

        InventoryBusinessController.MovementRequest request =
                InventoryBusinessController.MovementRequest.builder()
                        .productId(1L)
                        .warehouseId(1L)
                        .quantity(50)
                        .referenceDoc("PO-001")
                        .description("Stock inbound")
                        .build();

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/inventory/operations/inbound")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.quantity").value(50));

        verify(inventoryBusinessService, times(1))
                .recordInbound(1L, 1L, 50, "PO-001", "Stock inbound");
    }

    @Test
    @DisplayName("✓ POST /inbound - Enregistrer plusieurs entrées")
    void testRecordInboundMultiple() throws Exception {
        InventoryMovementDTO movement2 = InventoryMovementDTO.builder()
                .id(2L)
                .quantity(100)
                .build();

        when(inventoryBusinessService.recordInbound(2L, 2L, 100, "PO-002", "Stock inbound 2"))
                .thenReturn(movement2);

        InventoryBusinessController.MovementRequest request =
                InventoryBusinessController.MovementRequest.builder()
                        .productId(2L)
                        .warehouseId(2L)
                        .quantity(100)
                        .referenceDoc("PO-002")
                        .description("Stock inbound 2")
                        .build();

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/inventory/operations/inbound")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.quantity").value(100));

        verify(inventoryBusinessService, times(1))
                .recordInbound(2L, 2L, 100, "PO-002", "Stock inbound 2");
    }

    // ============================================================
    // TEST: POST /api/inventory/operations/outbound
    // ============================================================

    @Test
    @DisplayName("✓ POST /outbound - Enregistrer sortie de stock")
    void testRecordOutbound() throws Exception {
        when(inventoryBusinessService.recordOutbound(1L, 1L, 20, "SO-001", "Stock outbound"))
                .thenReturn(testMovement);

        InventoryBusinessController.MovementRequest request =
                InventoryBusinessController.MovementRequest.builder()
                        .productId(1L)
                        .warehouseId(1L)
                        .quantity(20)
                        .referenceDoc("SO-001")
                        .description("Stock outbound")
                        .build();

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/inventory/operations/outbound")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1));

        verify(inventoryBusinessService, times(1))
                .recordOutbound(1L, 1L, 20, "SO-001", "Stock outbound");
    }

    // ============================================================
    // TEST: POST /api/inventory/operations/adjustment
    // ============================================================

    @Test
    @DisplayName("✓ POST /adjustment - Enregistrer ajustement")
    void testRecordAdjustment() throws Exception {
        when(inventoryBusinessService.recordAdjustment(1L, 1L, 5, "ADJ-001", "Correction"))
                .thenReturn(testMovement);

        InventoryBusinessController.AdjustmentRequest request =
                InventoryBusinessController.AdjustmentRequest.builder()
                        .productId(1L)
                        .warehouseId(1L)
                        .adjustmentQuantity(5)
                        .referenceDoc("ADJ-001")
                        .reason("Correction")
                        .build();

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/inventory/operations/adjustment")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1));

        verify(inventoryBusinessService, times(1))
                .recordAdjustment(1L, 1L, 5, "ADJ-001", "Correction");
    }

    // ============================================================
    // TEST: POST /api/inventory/operations/allocate
    // ============================================================

    @Test
    @DisplayName("✓ POST /allocate - Allouer depuis plusieurs entrepôts")
    void testAllocateFromMultipleWarehouses() throws Exception {
        when(inventoryBusinessService.allocateFromMultipleWarehouses(1L, 50, List.of(1L, 2L)))
                .thenReturn(testAllocations);

        InventoryBusinessController.AllocationRequest request =
                InventoryBusinessController.AllocationRequest.builder()
                        .productId(1L)
                        .totalQuantity(50)
                        .warehouseIdsByPriority(List.of(1L, 2L))
                        .build();

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/inventory/operations/allocate")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.productId").value(1))
                .andExpect(jsonPath("$.requestedQuantity").value(50))
                .andExpect(jsonPath("$.totalAllocated").value(50))
                .andExpect(jsonPath("$.fullyAllocated").value(true));

        verify(inventoryBusinessService, times(1))
                .allocateFromMultipleWarehouses(1L, 50, List.of(1L, 2L));
    }

    @Test
    @DisplayName("✓ POST /allocate - Allocation partielle")
    void testAllocatePartial() throws Exception {
        List<InventoryBusinessService.AllocationResult> partialAllocations = new ArrayList<>();
        partialAllocations.add(InventoryBusinessService.AllocationResult.builder()
                .warehouseId(1L)
                .allocatedQuantity(30)
                .build());

        when(inventoryBusinessService.allocateFromMultipleWarehouses(1L, 50, List.of(1L, 2L)))
                .thenReturn(partialAllocations);

        InventoryBusinessController.AllocationRequest request =
                InventoryBusinessController.AllocationRequest.builder()
                        .productId(1L)
                        .totalQuantity(50)
                        .warehouseIdsByPriority(List.of(1L, 2L))
                        .build();

        String requestBody = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/inventory/operations/allocate")
                        .contentType("application/json")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalAllocated").value(30))
                .andExpect(jsonPath("$.shortage").value(20))
                .andExpect(jsonPath("$.fullyAllocated").value(false));

        verify(inventoryBusinessService, times(1))
                .allocateFromMultipleWarehouses(1L, 50, List.of(1L, 2L));
    }

    // ============================================================
    // TEST: GET /api/inventory/operations/out-of-stock
    // ============================================================

    @Test
    @DisplayName("✓ GET /out-of-stock - Produit en stock")
    void testCheckOutOfStockAvailable() throws Exception {
        when(inventoryBusinessService.isOutOfStock(1L, 1L)).thenReturn(false);

        mockMvc.perform(get("/api/inventory/operations/out-of-stock")
                        .param("productId", "1")
                        .param("warehouseId", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outOfStock").value(false))
                .andExpect(jsonPath("$.message").value("Stock disponible"));

        verify(inventoryBusinessService, times(1)).isOutOfStock(1L, 1L);
    }

    @Test
    @DisplayName("✓ GET /out-of-stock - Produit en rupture")
    void testCheckOutOfStockEmpty() throws Exception {
        when(inventoryBusinessService.isOutOfStock(2L, 2L)).thenReturn(true);

        mockMvc.perform(get("/api/inventory/operations/out-of-stock")
                        .param("productId", "2")
                        .param("warehouseId", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outOfStock").value(true))
                .andExpect(jsonPath("$.message").value("Produit en rupture de stock"));

        verify(inventoryBusinessService, times(1)).isOutOfStock(2L, 2L);
    }
}