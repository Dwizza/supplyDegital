package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.dto.SalesOrderCreateDTO;
import org.example.digitallogisticssupplychainplatform.dto.SalesOrderDTO;
import org.example.digitallogisticssupplychainplatform.dto.SalesOrderLineCreateDTO;
import org.example.digitallogisticssupplychainplatform.dto.SalesOrderUpdateDTO;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.exception.BusinessException;
import org.example.digitallogisticssupplychainplatform.exception.ResourceNotFoundException;
import org.example.digitallogisticssupplychainplatform.exception.StockUnavailableException;
import org.example.digitallogisticssupplychainplatform.mapper.SalesOrderMapper;
import org.example.digitallogisticssupplychainplatform.repository.ProductRepository;
import org.example.digitallogisticssupplychainplatform.repository.SalesOrderRepository;
import org.example.digitallogisticssupplychainplatform.repository.UserRepository;
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
@DisplayName("Tests - SalesOrderService FIXED")
class SalesOrderServiceTest {

    @Mock
    private SalesOrderRepository salesOrderRepository;

    @Mock
    private ProductRepository productRepository;

    @Mock
    private UserRepository clientRepository;

    @Mock
    private SalesOrderMapper salesOrderMapper;

    @InjectMocks
    private SalesOrderService salesOrderService;

    private SalesOrder testOrder;
    private SalesOrderDTO testOrderDTO;
    private User testClient;
    private Product testProduct1;
    private Product testProduct2;
    private SalesOrderLine testLine1;
    private SalesOrderLine testLine2;

    @BeforeEach
    void setUp() {

        testClient = new User();
        testClient.setId(1L);
        testClient.setUsername("client1");
        testClient.setEmail("client@test.com");

        // Créer les produits
        testProduct1 = new Product();
        testProduct1.setId(1L);
        testProduct1.setCode("PROD-001");
        testProduct1.setName("Laptop");

        testProduct2 = new Product();
        testProduct2.setId(2L);
        testProduct2.setCode("PROD-002");
        testProduct2.setName("Mouse");

        testLine1 = new SalesOrderLine();
        testLine1.setId(1L);
        testLine1.setProduct(testProduct1);
        testLine1.setQuantity(2);
        testLine1.setUnitPrice(new BigDecimal("1000.00"));
        testLine1.setBackordered(false);

        testLine2 = new SalesOrderLine();
        testLine2.setId(2L);
        testLine2.setProduct(testProduct2);
        testLine2.setQuantity(5);
        testLine2.setUnitPrice(new BigDecimal("50.00"));
        testLine2.setBackordered(false);

        testOrder = new SalesOrder();
        testOrder.setId(1L);
        testOrder.setClient(testClient);
        testOrder.setCreatedAt(LocalDateTime.now());
        List<SalesOrderLine> lines = new ArrayList<>();
        lines.add(testLine1);
        lines.add(testLine2);
        testOrder.setOrderLines(lines);

        testOrderDTO = SalesOrderDTO.builder()
                .id(1L)
                .clientId(1L)
                .clientName("client1")
                .createdAt(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("✓ Créer une nouvelle commande")
    void testCreateOrder() {
        SalesOrder orderToReturn = new SalesOrder();
        orderToReturn.setId(1L);
        orderToReturn.setClient(testClient);
        orderToReturn.setCreatedAt(LocalDateTime.now());
        List<SalesOrderLine> returnLines = new ArrayList<>();
        returnLines.add(testLine1);
        orderToReturn.setOrderLines(returnLines);

        SalesOrderCreateDTO createDTO = new SalesOrderCreateDTO();
        createDTO.setClientId(1L);

        SalesOrderLineCreateDTO lineDTO = new SalesOrderLineCreateDTO();
        lineDTO.setProductId(1L);
        lineDTO.setQuantity(2);
        lineDTO.setUnitPrice(new BigDecimal("1000.00"));

        createDTO.setOrderLines(List.of(lineDTO));

        when(clientRepository.findById(1L)).thenReturn(Optional.of(testClient));
        when(productRepository.existsById(1L)).thenReturn(true);
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct1));

        // ✅ FIX 1: Créez mappedOrder avec des données (pas une liste vide!)
        SalesOrder mappedOrder = new SalesOrder();
        mappedOrder.setClient(testClient);

        // Ajoutez au moins 1 ligne de commande
        List<SalesOrderLine> mappedLines = new ArrayList<>();
        SalesOrderLine mappedLine = new SalesOrderLine();
        mappedLine.setProduct(testProduct1);
        mappedLine.setQuantity(2);
        mappedLine.setUnitPrice(new BigDecimal("1000.00"));
        mappedLine.setBackordered(false);
        mappedLines.add(mappedLine);
        mappedOrder.setOrderLines(mappedLines); // ✅ Avec des données!

        when(salesOrderMapper.toEntity(createDTO, testClient)).thenReturn(mappedOrder);
        when(salesOrderRepository.save(any(SalesOrder.class))).thenReturn(orderToReturn);
        when(salesOrderMapper.toDTO(orderToReturn)).thenReturn(testOrderDTO);

        SalesOrderDTO result = salesOrderService.create(createDTO);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(clientRepository, times(1)).findById(1L);
        verify(salesOrderRepository, times(1)).save(any(SalesOrder.class));
        verify(salesOrderMapper, times(1)).toEntity(createDTO, testClient);
    }

    @Test
    @DisplayName("✓ Récupérer toutes les commandes")
    void testFindAll() {
        when(salesOrderRepository.findAll()).thenReturn(List.of(testOrder));
        when(salesOrderMapper.toDTO(testOrder)).thenReturn(testOrderDTO);
        var result = salesOrderService.findAll();
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(1L, result.get(0).getId());
        verify(salesOrderRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ Récupérer une commande par ID")
    void testFindById() {
        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(salesOrderMapper.toDTO(testOrder)).thenReturn(testOrderDTO);

        SalesOrderDTO result = salesOrderService.findById(1L);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(salesOrderRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("Récupérer les commandes par ID client")
    void testFindByClientId() {

        when(salesOrderRepository.findByClientId(1L)).thenReturn(List.of(testOrder));
        when(salesOrderMapper.toDTO(testOrder)).thenReturn(testOrderDTO);

        var result = salesOrderService.findByClientId(1L);


        assertNotNull(result);
        assertEquals(1, result.size());
        verify(salesOrderRepository, times(1)).findByClientId(1L);
    }

    @Test
    @DisplayName("✓ Mettre à jour une commande")
    void testUpdateOrder() {
        SalesOrderUpdateDTO updateDTO = new SalesOrderUpdateDTO();
        updateDTO.setReservedAt(LocalDateTime.now());

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(salesOrderRepository.save(any(SalesOrder.class))).thenReturn(testOrder);
        when(salesOrderMapper.toDTO(testOrder)).thenReturn(testOrderDTO);

        SalesOrderDTO result = salesOrderService.update(1L, updateDTO);

        assertNotNull(result);
        verify(salesOrderRepository, times(1)).findById(1L);
        verify(salesOrderRepository, times(1)).save(any(SalesOrder.class));
    }

    @Test
    @DisplayName("Supprimer une commande")
    void testDeleteOrder() {

        when(salesOrderRepository.existsById(1L)).thenReturn(true);

        salesOrderService.delete(1L);

        verify(salesOrderRepository, times(1)).existsById(1L);
        verify(salesOrderRepository, times(1)).deleteById(1L);
    }

    @Test
    @DisplayName("Erreur - Client introuvable lors de la création")
    void testCreateOrderClientNotFound() {

        SalesOrderCreateDTO createDTO = new SalesOrderCreateDTO();
        createDTO.setClientId(999L);

        when(clientRepository.findById(999L)).thenReturn(Optional.empty());


        assertThrows(ResourceNotFoundException.class, () ->
                salesOrderService.create(createDTO)
        );

        verify(salesOrderRepository, never()).save(any());
    }

    @Test
    @DisplayName(" Erreur - Produit introuvable lors de la création")
    void testCreateOrderProductNotFound() {

        SalesOrderCreateDTO createDTO = new SalesOrderCreateDTO();
        createDTO.setClientId(1L);

        SalesOrderLineCreateDTO lineDTO = new SalesOrderLineCreateDTO();
        lineDTO.setProductId(999L);
        lineDTO.setQuantity(2);
        lineDTO.setUnitPrice(new BigDecimal("1000.00"));

        createDTO.setOrderLines(List.of(lineDTO));

        when(clientRepository.findById(1L)).thenReturn(Optional.of(testClient));
        when(productRepository.existsById(999L)).thenReturn(false);

        assertThrows(ResourceNotFoundException.class, () ->
                salesOrderService.create(createDTO)
        );

        verify(salesOrderRepository, never()).save(any());
    }

    @Test
    @DisplayName(" Erreur - Commande introuvable lors de la récupération")
    void testFindByIdNotFound() {

        when(salesOrderRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                salesOrderService.findById(999L)
        );
    }

    @Test
    @DisplayName("Erreur - Commande introuvable lors de la mise à jour")
    void testUpdateOrderNotFound() {
        SalesOrderUpdateDTO updateDTO = new SalesOrderUpdateDTO();
        when(salesOrderRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                salesOrderService.update(999L, updateDTO)
        );

        verify(salesOrderRepository, never()).save(any());
    }

    @Test
    @DisplayName("Erreur - Commande introuvable lors de la suppression")
    void testDeleteOrderNotFound() {
        when(salesOrderRepository.existsById(999L)).thenReturn(false);

        assertThrows(ResourceNotFoundException.class, () ->
                salesOrderService.delete(999L)
        );

        verify(salesOrderRepository, never()).deleteById(anyLong());
    }

    @Test
    @DisplayName("✓ Créer une commande avec plusieurs produits")
    void testCreateOrderWithMultipleProducts() {
        SalesOrder orderToReturn = new SalesOrder();
        orderToReturn.setId(1L);
        orderToReturn.setClient(testClient);
        orderToReturn.setCreatedAt(LocalDateTime.now());
        List<SalesOrderLine> returnLines = new ArrayList<>();
        returnLines.add(testLine1);
        returnLines.add(testLine2);
        orderToReturn.setOrderLines(returnLines);

        SalesOrderCreateDTO createDTO = new SalesOrderCreateDTO();
        createDTO.setClientId(1L);

        SalesOrderLineCreateDTO lineDTO1 = new SalesOrderLineCreateDTO();
        lineDTO1.setProductId(1L);
        lineDTO1.setQuantity(2);
        lineDTO1.setUnitPrice(new BigDecimal("1000.00"));

        SalesOrderLineCreateDTO lineDTO2 = new SalesOrderLineCreateDTO();
        lineDTO2.setProductId(2L);
        lineDTO2.setQuantity(5);
        lineDTO2.setUnitPrice(new BigDecimal("50.00"));

        createDTO.setOrderLines(List.of(lineDTO1, lineDTO2));

        when(clientRepository.findById(1L)).thenReturn(Optional.of(testClient));
        when(productRepository.existsById(1L)).thenReturn(true);
        when(productRepository.existsById(2L)).thenReturn(true);
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct1));
        when(productRepository.findById(2L)).thenReturn(Optional.of(testProduct2));

        // ✅ FIX 2: Créez mappedOrder avec des données (pas une liste vide!)
        SalesOrder mappedOrder = new SalesOrder();
        mappedOrder.setClient(testClient);

        // Ajoutez les 2 lignes de commande
        List<SalesOrderLine> mappedLines = new ArrayList<>();

        SalesOrderLine mappedLine1 = new SalesOrderLine();
        mappedLine1.setProduct(testProduct1);
        mappedLine1.setQuantity(2);
        mappedLine1.setUnitPrice(new BigDecimal("1000.00"));
        mappedLine1.setBackordered(false);
        mappedLines.add(mappedLine1);

        SalesOrderLine mappedLine2 = new SalesOrderLine();
        mappedLine2.setProduct(testProduct2);
        mappedLine2.setQuantity(5);
        mappedLine2.setUnitPrice(new BigDecimal("50.00"));
        mappedLine2.setBackordered(false);
        mappedLines.add(mappedLine2);

        mappedOrder.setOrderLines(mappedLines); // ✅ Avec les 2 lignes!

        when(salesOrderMapper.toEntity(createDTO, testClient)).thenReturn(mappedOrder);
        when(salesOrderRepository.save(any(SalesOrder.class))).thenReturn(orderToReturn);
        when(salesOrderMapper.toDTO(orderToReturn)).thenReturn(testOrderDTO);

        SalesOrderDTO result = salesOrderService.create(createDTO);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(productRepository, times(2)).existsById(anyLong());
        verify(salesOrderRepository, times(1)).save(any(SalesOrder.class));
        verify(salesOrderMapper, times(1)).toEntity(createDTO, testClient);
    }

    @Test
    @DisplayName("✓ Récupérer les commandes vides d'un client")
    void testFindByClientIdEmpty() {

        when(salesOrderRepository.findByClientId(1L)).thenReturn(List.of());

        var result = salesOrderService.findByClientId(1L);

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(salesOrderRepository, times(1)).findByClientId(1L);
    }

    @Test
    @DisplayName("✓ Mettre à jour l'état de réservation d'une commande")
    void testUpdateOrderReservationStatus() {

        SalesOrderUpdateDTO updateDTO = new SalesOrderUpdateDTO();
        LocalDateTime reservedTime = LocalDateTime.now();
        updateDTO.setReservedAt(reservedTime);

        testOrder.setReservedAt(null);

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(salesOrderRepository.save(any(SalesOrder.class))).thenReturn(testOrder);
        when(salesOrderMapper.toDTO(testOrder)).thenReturn(testOrderDTO);

        SalesOrderDTO result = salesOrderService.update(1L, updateDTO);

        assertNotNull(result);
        verify(salesOrderRepository, times(1)).findById(1L);
        verify(salesOrderRepository, times(1)).save(any(SalesOrder.class));
    }

    @Test
    @DisplayName("✓ Mettre à jour l'état de livraison d'une commande")
    void testUpdateOrderDeliveryStatus() {
        SalesOrderUpdateDTO updateDTO = new SalesOrderUpdateDTO();
        LocalDateTime deliveredTime = LocalDateTime.now();
        updateDTO.setDeliveredAt(deliveredTime);

        testOrder.setDeliveredAt(null);

        when(salesOrderRepository.findById(1L)).thenReturn(Optional.of(testOrder));
        when(salesOrderRepository.save(any(SalesOrder.class))).thenReturn(testOrder);
        when(salesOrderMapper.toDTO(testOrder)).thenReturn(testOrderDTO);

        SalesOrderDTO result = salesOrderService.update(1L, updateDTO);

        assertNotNull(result);
        verify(salesOrderRepository, times(1)).findById(1L);
        verify(salesOrderRepository, times(1)).save(any(SalesOrder.class));
    }
}