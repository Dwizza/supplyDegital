package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.exception.BusinessException;
import org.example.digitallogisticssupplychainplatform.exception.ResourceNotFoundException;
import org.example.digitallogisticssupplychainplatform.exception.StockUnavailableException;
import org.example.digitallogisticssupplychainplatform.repository.InventoryRepository;
import org.example.digitallogisticssupplychainplatform.repository.SalesOrderRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - SalesOrderBusinessService FIXED")
class SalesOrderBusinessServiceTest {

    @Mock
    private SalesOrderRepository salesOrderRepository;

    @Mock
    private InventoryBusinessService inventoryBusinessService;

    @Mock
    private InventoryRepository inventoryRepository;

    @InjectMocks
    private SalesOrderBusinessService salesOrderBusinessService;

    private SalesOrder testOrder;
    private SalesOrderLine testLine1;
    private SalesOrderLine testLine2;
    private Product product1;
    private Product product2;
    private WareHouse warehouse;
    private Inventory inventory1;
    private Inventory inventory2;
    private User testClient;

    @BeforeEach
    void setUp() {
        warehouse = new WareHouse();
        warehouse.setId(1L);
        warehouse.setCode("WH-001");
        warehouse.setName("Main Warehouse");

        testClient = new User();
        testClient.setId(1L);
        testClient.setUsername("client1");
        testClient.setEmail("client@test.com");

        product1 = new Product();
        product1.setId(1L);
        product1.setCode("PROD-001");
        product1.setName("Laptop");
        product1.setActive(true);
        product1.setStatus(ProductStatus.ACTIVE);

        product2 = new Product();
        product2.setId(2L);
        product2.setCode("PROD-002");
        product2.setName("Monitor");
        product2.setActive(true);
        product2.setStatus(ProductStatus.ACTIVE);

        inventory1 = new Inventory();
        inventory1.setId(1L);
        inventory1.setProduct(product1);
        inventory1.setWarehouse(warehouse);
        inventory1.setQtyOnHand(100);
        inventory1.setQtyReserved(20);

        inventory2 = new Inventory();
        inventory2.setId(2L);
        inventory2.setProduct(product2);
        inventory2.setWarehouse(warehouse);
        inventory2.setQtyOnHand(50);
        inventory2.setQtyReserved(10);

        testOrder = new SalesOrder();
        testOrder.setId(1L);
        testOrder.setClient(testClient);
        testOrder.setCreatedAt(LocalDateTime.now());

        testLine1 = new SalesOrderLine();
        testLine1.setId(1L);
        testLine1.setProduct(product1);
        testLine1.setQuantity(30);
        testLine1.setUnitPrice(new BigDecimal("50.00"));
        testLine1.setBackordered(false);

        testLine2 = new SalesOrderLine();
        testLine2.setId(2L);
        testLine2.setProduct(product2);
        testLine2.setQuantity(20);
        testLine2.setUnitPrice(new BigDecimal("30.00"));
        testLine2.setBackordered(false);

        List<SalesOrderLine> lines = new ArrayList<>();
        lines.add(testLine1);
        lines.add(testLine2);
        testOrder.setOrderLines(lines);
    }

    @Test
    @DisplayName(" Réserver complètement une commande")
    void testReserveOrderComplete() {

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(inventoryRepository.findByProductIdAndWarehouseId(1L, 1L)).thenReturn(inventory1);
        when(inventoryRepository.findByProductIdAndWarehouseId(2L, 1L)).thenReturn(inventory2);
        doNothing().when(inventoryBusinessService).reserveStock(anyLong(), anyLong(), anyInt(), anyString());

        SalesOrderBusinessService.ReservationResult result =
                salesOrderBusinessService.reserveOrder(1L, 1L);


        assertNotNull(result);
        assertTrue(result.getFullyReserved());
        assertNotNull(result.getReservedAt());
        verify(inventoryBusinessService, times(2)).reserveStock(anyLong(), anyLong(), anyInt(), anyString());
        verify(salesOrderRepository, times(1)).save(testOrder);
    }

    @Test
    @DisplayName(" Réserver partiellement avec backorder")
    void testReserveOrderWithBackorder() {

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(inventoryRepository.findByProductIdAndWarehouseId(1L, 1L)).thenReturn(inventory1);
        when(inventoryRepository.findByProductIdAndWarehouseId(2L, 1L)).thenReturn(inventory2);

        // ✅ FIX 3: Mock reserveStock pour lever l'exception
        // Le premier appel lève l'exception (backorder), le second fonctionne
        doThrow(new StockUnavailableException("Insufficient stock"))
                .doNothing()
                .when(inventoryBusinessService)
                .reserveStock(anyLong(), anyLong(), anyInt(), anyString());

        SalesOrderBusinessService.ReservationResult result =
                salesOrderBusinessService.reserveOrder(1L, 1L);


        assertNotNull(result);
        assertFalse(result.getFullyReserved()); // Pas complètement réservée
        assertTrue(result.getBackorders().size() > 0); // Y a des backorders
        verify(salesOrderRepository, times(1)).save(testOrder);
    }

    @Test
    @DisplayName(" Vérifier la disponibilité")
    void testCheckAvailability() {

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(inventoryRepository.findByProductIdAndWarehouseId(1L, 1L)).thenReturn(inventory1);
        when(inventoryRepository.findByProductIdAndWarehouseId(2L, 1L)).thenReturn(inventory2);


        SalesOrderBusinessService.AvailabilityCheck result =
                salesOrderBusinessService.checkAvailability(1L, 1L);


        assertNotNull(result);
        assertNotNull(result.getProducts());
        assertEquals(2, result.getProducts().size());
        verify(inventoryRepository, times(2)).findByProductIdAndWarehouseId(anyLong(), anyLong());
    }

    @Test
    @DisplayName(" Expédier une commande réservée")
    void testShipReservedOrder() {

        testOrder.setReservedAt(LocalDateTime.now());
        testLine1.setBackordered(false);
        testLine2.setBackordered(false);

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));

        // ✅ FIX 1: recordOutbound retourne InventoryMovementDTO (pas void!)
        // Créez des DTO mock appropriés
        InventoryMovementDTO movement1 = new InventoryMovementDTO();
        movement1.setId(1L);
        movement1.setQuantity(30);


        InventoryMovementDTO movement2 = new InventoryMovementDTO();
        movement2.setId(2L);
        movement2.setQuantity(20);


        // Mock recordOutbound pour retourner les DTO
        when(inventoryBusinessService.recordOutbound(anyLong(), anyLong(), anyInt(), anyString(), anyString()))
                .thenReturn(movement1)  // Première fois
                .thenReturn(movement2); // Deuxième fois

        SalesOrderBusinessService.ShipmentResult result =
                salesOrderBusinessService.shipOrder(1L, 1L);


        assertNotNull(result);
        assertNotNull(result.getShippedAt());
        assertEquals(2, result.getMovements().size());
        verify(inventoryBusinessService, times(2)).recordOutbound(anyLong(), anyLong(), anyInt(), anyString(), anyString());
        verify(salesOrderRepository, times(1)).save(testOrder);
    }

    @Test
    @DisplayName(" Expédier avec backorders")
    void testShipWithBackorders() {

        testOrder.setReservedAt(LocalDateTime.now());
        testLine1.setBackordered(true);
        testLine2.setBackordered(false);

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));

        // ✅ FIX 2: recordOutbound retourne InventoryMovementDTO (pas void!)
        InventoryMovementDTO movement = new InventoryMovementDTO();
        movement.setId(1L);
        movement.setQuantity(20);


        // Mock recordOutbound pour retourner le DTO
        when(inventoryBusinessService.recordOutbound(anyLong(), anyLong(), anyInt(), anyString(), anyString()))
                .thenReturn(movement);

        SalesOrderBusinessService.ShipmentResult result =
                salesOrderBusinessService.shipOrder(1L, 1L);


        assertNotNull(result);
        assertNotNull(result.getShippedAt());
        assertEquals(1, result.getMovements().size()); // Seulement 1 ligne (pas de backorder)
        verify(inventoryBusinessService, times(1)).recordOutbound(anyLong(), anyLong(), anyInt(), anyString(), anyString());
    }

    @Test
    @DisplayName("Ne pas expédier sans réservation")
    void testCannotShipWithoutReservation() {

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));

        assertThrows(BusinessException.class, () ->
                salesOrderBusinessService.shipOrder(1L, 1L)
        );

        verify(inventoryBusinessService, never()).recordOutbound(anyLong(), anyLong(), anyInt(), anyString(), anyString());
    }

    @Test
    @DisplayName(" Livrer une commande")
    void testDeliverOrder() {

        testOrder.setShippedAt(LocalDateTime.now());
        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));

        salesOrderBusinessService.deliverOrder(1L);


        assertNotNull(testOrder.getDeliveredAt());
        verify(salesOrderRepository, times(1)).save(testOrder);
    }

    @Test
    @DisplayName("Ne pas livrer sans expédition")
    void testCannotDeliverWithoutShipment() {
        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));

        assertThrows(BusinessException.class, () ->
                salesOrderBusinessService.deliverOrder(1L)
        );
    }

    @Test
    @DisplayName(" Annuler une commande")
    void testCancelOrder() {
        testOrder.setReservedAt(LocalDateTime.now());
        testLine1.setBackordered(false);
        testLine2.setBackordered(false);

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(inventoryRepository.findByProductIdAndWarehouseId(1L, 1L)).thenReturn(inventory1);
        when(inventoryRepository.findByProductIdAndWarehouseId(2L, 1L)).thenReturn(inventory2);
        doNothing().when(inventoryBusinessService).releaseReservation(anyLong(), anyLong(), anyInt(), anyString());

        SalesOrderBusinessService.CancellationResult result =
                salesOrderBusinessService.cancelOrder(1L, "Client request", 1L);


        assertNotNull(result);
        assertNotNull(result.getCancelledAt());
        assertEquals("Client request", result.getReason());
        verify(inventoryBusinessService, times(2)).releaseReservation(anyLong(), anyLong(), anyInt(), anyString());
        verify(salesOrderRepository, times(1)).delete(testOrder);
    }

    @Test
    @DisplayName("Ne pas annuler une commande expédiée")
    void testCannotCancelShippedOrder() {
        testOrder.setShippedAt(LocalDateTime.now());
        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));

        assertThrows(BusinessException.class, () ->
                salesOrderBusinessService.cancelOrder(1L, "Test", 1L)
        );

        verify(inventoryBusinessService, never()).releaseReservation(anyLong(), anyLong(), anyInt(), anyString());
    }

    @Test
    @DisplayName("Ne pas annuler une commande livrée")
    void testCannotCancelDeliveredOrder() {
        testOrder.setDeliveredAt(LocalDateTime.now());
        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));

        assertThrows(BusinessException.class, () ->
                salesOrderBusinessService.cancelOrder(1L, "Test", 1L)
        );

        verify(salesOrderRepository, never()).delete(any());
    }

    @Test
    @DisplayName("Commande introuvable")
    void testOrderNotFound() {
        when(salesOrderRepository.findById(999L)).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () ->
                salesOrderBusinessService.reserveOrder(999L, 1L)
        );
    }

    @Test
    @DisplayName("Produit inactif")
    void testCannotReserveInactiveProduct() {

        product1.setActive(false);
        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));

        assertThrows(BusinessException.class, () ->
                salesOrderBusinessService.reserveOrder(1L, 1L)
        );

        verify(inventoryBusinessService, never()).reserveStock(anyLong(), anyLong(), anyInt(), anyString());
    }

    @Test
    @DisplayName("Ne pas réserver deux fois")
    void testCannotReserveTwice() {
        testOrder.setReservedAt(LocalDateTime.now());
        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));

        assertThrows(BusinessException.class, () ->
                salesOrderBusinessService.reserveOrder(1L, 1L)
        );

        verify(inventoryBusinessService, never()).reserveStock(anyLong(), anyLong(), anyInt(), anyString());
    }

    @Test
    @DisplayName(" Vérifier la disponibilité complète")
    void testCheckAvailabilityComplete() {
        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(inventoryRepository.findByProductIdAndWarehouseId(1L, 1L)).thenReturn(inventory1);
        when(inventoryRepository.findByProductIdAndWarehouseId(2L, 1L)).thenReturn(inventory2);

        SalesOrderBusinessService.AvailabilityCheck result =
                salesOrderBusinessService.checkAvailability(1L, 1L);


        assertNotNull(result);
        assertTrue(result.getCanReserveCompletely());
        assertEquals(2, result.getProducts().size());
    }

    @Test
    @DisplayName(" Vérifier la disponibilité insuffisante")
    void testCheckAvailabilityInsufficient() {
        inventory1.setQtyOnHand(10);
        inventory1.setQtyReserved(5);

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(inventoryRepository.findByProductIdAndWarehouseId(1L, 1L)).thenReturn(inventory1);
        when(inventoryRepository.findByProductIdAndWarehouseId(2L, 1L)).thenReturn(inventory2);

        SalesOrderBusinessService.AvailabilityCheck result =
                salesOrderBusinessService.checkAvailability(1L, 1L);


        assertNotNull(result);
        assertFalse(result.getCanReserveCompletely());
    }

    @Test
    @DisplayName("Commande introuvable lors du livraison")
    void testDeliverOrderNotFound() {

        when(salesOrderRepository.findById(999L)).thenReturn(Optional.empty());


        assertThrows(ResourceNotFoundException.class, () ->
                salesOrderBusinessService.deliverOrder(999L)
        );
    }

    @Test
    @DisplayName("Commande introuvable lors de l'annulation")
    void testCancelOrderNotFound() {

        when(salesOrderRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                salesOrderBusinessService.cancelOrder(999L, "Test", 1L)
        );

        verify(salesOrderRepository, never()).delete(any());
    }

    @Test
    @DisplayName(" Vérifier les commandes sans stock")
    void testCheckAvailabilityNoStock() {

        inventory1.setQtyOnHand(0);
        inventory1.setQtyReserved(0);

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(inventoryRepository.findByProductIdAndWarehouseId(1L, 1L)).thenReturn(inventory1);
        when(inventoryRepository.findByProductIdAndWarehouseId(2L, 1L)).thenReturn(inventory2);


        SalesOrderBusinessService.AvailabilityCheck result =
                salesOrderBusinessService.checkAvailability(1L, 1L);


        assertNotNull(result);
        assertFalse(result.getCanReserveCompletely());
    }
}