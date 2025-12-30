package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.CreatePurchaseOrderRequest;
import org.example.digitallogisticssupplychainplatform.dto.PurchaseOrderDTO;
import org.example.digitallogisticssupplychainplatform.dto.PurchaseOrderLineRequest;
import org.example.digitallogisticssupplychainplatform.dto.UpdatePurchaseOrderStatusRequest;
import org.example.digitallogisticssupplychainplatform.entity.Product;
import org.example.digitallogisticssupplychainplatform.entity.PurchaseOrder;
import org.example.digitallogisticssupplychainplatform.entity.PurchaseOrderStatus;
import org.example.digitallogisticssupplychainplatform.entity.Supplier;
import org.example.digitallogisticssupplychainplatform.entity.User;
import org.example.digitallogisticssupplychainplatform.mapper.PurchaseOrderMapper;
import org.example.digitallogisticssupplychainplatform.repository.PurchaseOrderRepository;
import org.example.digitallogisticssupplychainplatform.repository.SupplierRepository;
import org.example.digitallogisticssupplychainplatform.repository.UserRepository;
import org.example.digitallogisticssupplychainplatform.repository.ProductRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - PurchaseOrderService")
class PurchaseOrderServiceTest {

    @Mock
    private PurchaseOrderRepository purchaseOrderRepository;

    @Mock
    private SupplierRepository supplierRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private ProductRepository productRepository;

    @Mock
    private PurchaseOrderMapper purchaseOrderMapper;

    private PurchaseOrderService purchaseOrderService;

    private Supplier testSupplier;
    private User testUser;
    private Product testProduct;
    private PurchaseOrder testPurchaseOrder;
    private PurchaseOrderDTO testPurchaseOrderDTO;

    @BeforeEach
    void setUp() {
        purchaseOrderService = new PurchaseOrderService(
                purchaseOrderRepository,
                supplierRepository,
                userRepository,
                productRepository,
                purchaseOrderMapper
        );

        testSupplier = new Supplier();
        testSupplier.setId(1L);
        testSupplier.setName("Supplier A");

        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("Manager 1");

        testProduct = new Product();
        testProduct.setId(1L);
        testProduct.setName("Product 1");

        testPurchaseOrder = new PurchaseOrder();
        testPurchaseOrder.setId(1L);
        testPurchaseOrder.setStatus(PurchaseOrderStatus.PENDING);
        testPurchaseOrder.setSupplier(testSupplier);
        testPurchaseOrder.setWarehouseManager(testUser);

        testPurchaseOrderDTO = new PurchaseOrderDTO();
        testPurchaseOrderDTO.setId(1L);
        testPurchaseOrderDTO.setStatus("DRAFT");
        testPurchaseOrderDTO.setSupplierId(1L);
        testPurchaseOrderDTO.setWarehouseManagerId(1L);
    }



    @Test
    @DisplayName("✓ createPurchaseOrder - Créer commande d'achat avec succès")
    void testCreatePurchaseOrderSuccess()  {
        CreatePurchaseOrderRequest request = new CreatePurchaseOrderRequest();
        request.setSupplierId(1L);
        request.setWarehouseManagerId(1L);
        request.setExpectedDelivery(LocalDateTime.now().plusDays(7));
        request.setOrderLines(new ArrayList<>());

        when(supplierRepository.findById(1L)).thenReturn(Optional.of(testSupplier));
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(purchaseOrderMapper.toEntity((request), testSupplier, testUser))
                .thenReturn(testPurchaseOrder);
        when(purchaseOrderRepository.save(any(PurchaseOrder.class))).thenReturn(testPurchaseOrder);
        when(purchaseOrderMapper.toDTO(testPurchaseOrder)).thenReturn(testPurchaseOrderDTO);

        PurchaseOrderDTO result = purchaseOrderService.createPurchaseOrder(request);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(supplierRepository, times(1)).findById(1L);
        verify(userRepository, times(1)).findById(1L);
        verify(purchaseOrderRepository, times(1)).save(any(PurchaseOrder.class));
    }

    @Test
    @DisplayName("createPurchaseOrder - Fournisseur non trouvé")
    void testCreatePurchaseOrderSupplierNotFound() {
        CreatePurchaseOrderRequest request = new CreatePurchaseOrderRequest();
        request.setSupplierId(999L);
        request.setWarehouseManagerId(1L);
        request.setOrderLines(new ArrayList<>());

        when(supplierRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> purchaseOrderService.createPurchaseOrder(request));
        verify(supplierRepository, times(1)).findById(999L);
    }

    @Test
    @DisplayName("❌ createPurchaseOrder - Manager non trouvé")
    void testCreatePurchaseOrderManagerNotFound() {
        CreatePurchaseOrderRequest request = new CreatePurchaseOrderRequest();
        request.setSupplierId(1L);
        request.setWarehouseManagerId(999L);
        request.setOrderLines(new ArrayList<>());

        when(supplierRepository.findById(1L)).thenReturn(Optional.of(testSupplier));
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> purchaseOrderService.createPurchaseOrder(request));
        verify(userRepository, times(1)).findById(999L);
    }

    @Test
    @DisplayName("✓ createPurchaseOrder - Créer avec lignes de commande")
    void testCreatePurchaseOrderWithLines()  {
        PurchaseOrderLineRequest lineRequest = new PurchaseOrderLineRequest();
        lineRequest.setProductId(1L);
        lineRequest.setQuantity(10);

        CreatePurchaseOrderRequest request = new CreatePurchaseOrderRequest();
        request.setSupplierId(1L);
        request.setWarehouseManagerId(1L);
        request.setOrderLines(List.of(lineRequest));

        when(supplierRepository.findById(1L)).thenReturn(Optional.of(testSupplier));
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(purchaseOrderMapper.toEntity(request,testSupplier, testUser))
                .thenReturn(testPurchaseOrder);
        org.example.digitallogisticssupplychainplatform.entity.PurchaseOrderLine mockLine =
                new org.example.digitallogisticssupplychainplatform.entity.PurchaseOrderLine();
        when(purchaseOrderMapper.toLineEntity(any(PurchaseOrderLineRequest.class), eq(testProduct)))
                .thenReturn(mockLine);

        when(purchaseOrderRepository.save(any(PurchaseOrder.class))).thenReturn(testPurchaseOrder);
        when(purchaseOrderMapper.toDTO(testPurchaseOrder)).thenReturn(testPurchaseOrderDTO);

        PurchaseOrderDTO result = purchaseOrderService.createPurchaseOrder(request);

        assertNotNull(result);
        verify(productRepository, times(1)).findById(1L);
    }

    // ============================================================
    // TEST: getAllPurchaseOrders
    // ============================================================

    @Test
    @DisplayName("✓ getAllPurchaseOrders - Récupérer toutes les commandes")
    void testGetAllPurchaseOrders() {
        List<PurchaseOrder> orders = new ArrayList<>();
        orders.add(testPurchaseOrder);

        when(purchaseOrderRepository.findAll()).thenReturn(orders);
        when(purchaseOrderMapper.toDTO(testPurchaseOrder)).thenReturn(testPurchaseOrderDTO);

        List<PurchaseOrderDTO> result = purchaseOrderService.getAllPurchaseOrders();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(purchaseOrderRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ getAllPurchaseOrders - Liste vide")
    void testGetAllPurchaseOrdersEmpty() {
        when(purchaseOrderRepository.findAll()).thenReturn(new ArrayList<>());

        List<PurchaseOrderDTO> result = purchaseOrderService.getAllPurchaseOrders();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(purchaseOrderRepository, times(1)).findAll();
    }

    // ============================================================
    // TEST: getPurchaseOrderById
    // ============================================================

    @Test
    @DisplayName("✓ getPurchaseOrderById - Récupérer commande par ID")
    void testGetPurchaseOrderById() {
        when(purchaseOrderRepository.findById(1L)).thenReturn(Optional.of(testPurchaseOrder));
        when(purchaseOrderMapper.toDTO(testPurchaseOrder)).thenReturn(testPurchaseOrderDTO);

        PurchaseOrderDTO result = purchaseOrderService.getPurchaseOrderById(1L);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(purchaseOrderRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("❌ getPurchaseOrderById - Commande non trouvée")
    void testGetPurchaseOrderByIdNotFound() {
        when(purchaseOrderRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> purchaseOrderService.getPurchaseOrderById(999L));
        verify(purchaseOrderRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: updatePurchaseOrderStatus
    // ============================================================

    @Test
    @DisplayName("✓ updatePurchaseOrderStatus - Mettre à jour le statut")
    void testUpdatePurchaseOrderStatus() {
        UpdatePurchaseOrderStatusRequest request = new UpdatePurchaseOrderStatusRequest();
        request.setStatus("CONFIRMED");

        PurchaseOrder updatedOrder = new PurchaseOrder();
        updatedOrder.setId(1L);
        updatedOrder.setStatus(PurchaseOrderStatus.CONFIRMED);

        PurchaseOrderDTO updatedDTO = new PurchaseOrderDTO();
        updatedDTO.setId(1L);
        updatedDTO.setStatus("CONFIRMED");

        when(purchaseOrderRepository.findById(1L)).thenReturn(Optional.of(testPurchaseOrder));
        when(purchaseOrderRepository.save(any(PurchaseOrder.class))).thenReturn(updatedOrder);
        when(purchaseOrderMapper.toDTO(updatedOrder)).thenReturn(updatedDTO);

        PurchaseOrderDTO result = purchaseOrderService.updatePurchaseOrderStatus(1L, request);

        assertNotNull(result);
        assertEquals("CONFIRMED", result.getStatus());
        verify(purchaseOrderRepository, times(1)).findById(1L);
        verify(purchaseOrderRepository, times(1)).save(any(PurchaseOrder.class));
    }

    @Test
    @DisplayName("❌ updatePurchaseOrderStatus - Commande non trouvée")
    void testUpdatePurchaseOrderStatusNotFound() {
        UpdatePurchaseOrderStatusRequest request = new UpdatePurchaseOrderStatusRequest();
        request.setStatus("CONFIRMED");

        when(purchaseOrderRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> purchaseOrderService.updatePurchaseOrderStatus(999L, request));
        verify(purchaseOrderRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: getPurchaseOrdersByStatus
    // ============================================================

    @Test
    @DisplayName("✓ getPurchaseOrdersByStatus - Récupérer par statut PENDING")
    void testGetPurchaseOrdersByStatusPending() {
        List<PurchaseOrder> orders = new ArrayList<>();
        orders.add(testPurchaseOrder);

        when(purchaseOrderRepository.findByStatus(PurchaseOrderStatus.PENDING)).thenReturn(orders);
        when(purchaseOrderMapper.toDTO(testPurchaseOrder)).thenReturn(testPurchaseOrderDTO);

        List<PurchaseOrderDTO> result = purchaseOrderService.getPurchaseOrdersByStatus("PENDING");

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(purchaseOrderRepository, times(1)).findByStatus(PurchaseOrderStatus.PENDING);
    }

    @Test
    @DisplayName("✓ getPurchaseOrdersByStatus - Récupérer par statut CONFIRMED")
    void testGetPurchaseOrdersByStatusConfirmed() {
        List<PurchaseOrder> orders = new ArrayList<>();

        when(purchaseOrderRepository.findByStatus(PurchaseOrderStatus.CONFIRMED)).thenReturn(orders);

        List<PurchaseOrderDTO> result = purchaseOrderService.getPurchaseOrdersByStatus("CONFIRMED");

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(purchaseOrderRepository, times(1)).findByStatus(PurchaseOrderStatus.CONFIRMED);
    }

    // ============================================================
    // TEST: getPurchaseOrdersBySupplier
    // ============================================================

    @Test
    @DisplayName("✓ getPurchaseOrdersBySupplier - Récupérer par fournisseur")
    void testGetPurchaseOrdersBySupplier() {
        List<PurchaseOrder> orders = new ArrayList<>();
        orders.add(testPurchaseOrder);

        when(purchaseOrderRepository.findBySupplierId(1L)).thenReturn(orders);
        when(purchaseOrderMapper.toDTO(testPurchaseOrder)).thenReturn(testPurchaseOrderDTO);

        List<PurchaseOrderDTO> result = purchaseOrderService.getPurchaseOrdersBySupplier(1L);

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(purchaseOrderRepository, times(1)).findBySupplierId(1L);
    }

    @Test
    @DisplayName("✓ getPurchaseOrdersBySupplier - Fournisseur sans commandes")
    void testGetPurchaseOrdersBySupplierEmpty() {
        when(purchaseOrderRepository.findBySupplierId(999L)).thenReturn(new ArrayList<>());

        List<PurchaseOrderDTO> result = purchaseOrderService.getPurchaseOrdersBySupplier(999L);

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(purchaseOrderRepository, times(1)).findBySupplierId(999L);
    }

    // ============================================================
    // TEST: getPurchaseOrdersByWarehouseManager
    // ============================================================

    @Test
    @DisplayName("✓ getPurchaseOrdersByWarehouseManager - Récupérer par manager")
    void testGetPurchaseOrdersByWarehouseManager() {
        List<PurchaseOrder> orders = new ArrayList<>();
        orders.add(testPurchaseOrder);

        when(purchaseOrderRepository.findByWarehouseManagerId(1L)).thenReturn(orders);
        when(purchaseOrderMapper.toDTO(testPurchaseOrder)).thenReturn(testPurchaseOrderDTO);

        List<PurchaseOrderDTO> result = purchaseOrderService.getPurchaseOrdersByWarehouseManager(1L);

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(purchaseOrderRepository, times(1)).findByWarehouseManagerId(1L);
    }

    @Test
    @DisplayName("✓ getPurchaseOrdersByWarehouseManager - Manager sans commandes")
    void testGetPurchaseOrdersByWarehouseManagerEmpty() {
        when(purchaseOrderRepository.findByWarehouseManagerId(999L)).thenReturn(new ArrayList<>());

        List<PurchaseOrderDTO> result = purchaseOrderService.getPurchaseOrdersByWarehouseManager(999L);

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(purchaseOrderRepository, times(1)).findByWarehouseManagerId(999L);
    }

    // ============================================================
    // TEST: deletePurchaseOrder
    // ============================================================

    @Test
    @DisplayName("✓ deletePurchaseOrder - Supprimer commande d'achat")
    void testDeletePurchaseOrder() {
        when(purchaseOrderRepository.findById(1L)).thenReturn(Optional.of(testPurchaseOrder));
        doNothing().when(purchaseOrderRepository).delete(testPurchaseOrder);

        purchaseOrderService.deletePurchaseOrder(1L);

        verify(purchaseOrderRepository, times(1)).findById(1L);
        verify(purchaseOrderRepository, times(1)).delete(testPurchaseOrder);
    }

    @Test
    @DisplayName("❌ deletePurchaseOrder - Commande non trouvée")
    void testDeletePurchaseOrderNotFound() {
        when(purchaseOrderRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> purchaseOrderService.deletePurchaseOrder(999L));
        verify(purchaseOrderRepository, times(1)).findById(999L);
        verify(purchaseOrderRepository, never()).delete(any());
    }

    // ============================================================
    // TEST: Multiple operations
    // ============================================================

    @Test
    @DisplayName("✓ Opérations multiples - Créer et récupérer")
    void testCreateAndGet() {
        CreatePurchaseOrderRequest createRequest = new CreatePurchaseOrderRequest();
        createRequest.setSupplierId(1L);
        createRequest.setWarehouseManagerId(1L);
        createRequest.setOrderLines(new ArrayList<>());

        when(supplierRepository.findById(1L)).thenReturn(Optional.of(testSupplier));
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(purchaseOrderMapper.toEntity(any(), any(), any())).thenReturn(testPurchaseOrder);
        when(purchaseOrderRepository.save(any())).thenReturn(testPurchaseOrder);
        when(purchaseOrderMapper.toDTO(testPurchaseOrder)).thenReturn(testPurchaseOrderDTO);

        PurchaseOrderDTO created = purchaseOrderService.createPurchaseOrder(createRequest);
        assertNotNull(created);

        when(purchaseOrderRepository.findById(1L)).thenReturn(Optional.of(testPurchaseOrder));
        PurchaseOrderDTO retrieved = purchaseOrderService.getPurchaseOrderById(1L);
        assertNotNull(retrieved);
        assertEquals(created.getId(), retrieved.getId());
    }

    @Test
    @DisplayName("✓ Opérations multiples - Créer et mettre à jour statut")
    void testCreateAndUpdateStatus() {
        CreatePurchaseOrderRequest createRequest = new CreatePurchaseOrderRequest();
        createRequest.setSupplierId(1L);
        createRequest.setWarehouseManagerId(1L);
        createRequest.setOrderLines(new ArrayList<>());

        when(supplierRepository.findById(1L)).thenReturn(Optional.of(testSupplier));
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(purchaseOrderMapper.toEntity(any(), any(), any())).thenReturn(testPurchaseOrder);
        when(purchaseOrderRepository.save(any())).thenReturn(testPurchaseOrder);
        when(purchaseOrderMapper.toDTO(testPurchaseOrder)).thenReturn(testPurchaseOrderDTO);

        PurchaseOrderDTO created = purchaseOrderService.createPurchaseOrder(createRequest);
        assertNotNull(created);

        UpdatePurchaseOrderStatusRequest updateRequest = new UpdatePurchaseOrderStatusRequest();
        updateRequest.setStatus("CONFIRMED");

        when(purchaseOrderRepository.findById(1L)).thenReturn(Optional.of(testPurchaseOrder));
        when(purchaseOrderRepository.save(any())).thenReturn(testPurchaseOrder);

        PurchaseOrderDTO updated = purchaseOrderService.updatePurchaseOrderStatus(1L, updateRequest);
        assertNotNull(updated);
    }
}