package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.InventoryDTO;
import org.example.digitallogisticssupplychainplatform.entity.Inventory;
import org.example.digitallogisticssupplychainplatform.entity.Product;
import org.example.digitallogisticssupplychainplatform.entity.WareHouse;
import org.example.digitallogisticssupplychainplatform.exception.ResourceNotFoundException;
import org.example.digitallogisticssupplychainplatform.mapper.InventoryMapper;
import org.example.digitallogisticssupplychainplatform.repository.InventoryRepository;
import org.example.digitallogisticssupplychainplatform.repository.ProductRepository;
import org.example.digitallogisticssupplychainplatform.repository.WareHouseRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - InventoryService")
class InventoryServiceTest {

    @Mock
    private InventoryRepository inventoryRepository;

    @Mock
    private WareHouseRepository warehouseRepository;

    @Mock
    private ProductRepository productRepository;

    @Mock
    private InventoryMapper inventoryMapper;

    @InjectMocks
    private InventoryServiceImpl inventoryService;

    private Inventory testInventory;
    private InventoryDTO testInventoryDTO;
    private WareHouse testWarehouse;
    private Product testProduct;

    @BeforeEach
    void setUp() {
        testWarehouse = new WareHouse();
        testWarehouse.setId(1L);
        testWarehouse.setCode("WH-001");
        testWarehouse.setName("Main Warehouse");

        testProduct = new Product();
        testProduct.setId(1L);
        testProduct.setCode("PROD-001");
        testProduct.setName("Laptop");

        testInventory = new Inventory();
        testInventory.setId(1L);
        testInventory.setProduct(testProduct);
        testInventory.setWarehouse(testWarehouse);
        testInventory.setQtyOnHand(100);
        testInventory.setQtyReserved(20);

        testInventoryDTO = InventoryDTO.builder()
                .id(1L)
                .qtyOnHand(100)
                .qtyReserved(20)
                .warehouseId(1L)
                .warehouseCode("WH-001")
                .warehouseName("Main Warehouse")
                .productId(1L)
                .productCode("PROD-001")
                .productName("Laptop")
                .build();
    }

    @Test
    @DisplayName(" Récupérer tous les inventaires")
    void testFindAll() {
        when(inventoryRepository.findAllWithWarehouse()).thenReturn(List.of(testInventory));
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);
        var result = inventoryService.findAll();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(inventoryRepository, times(1)).findAllWithWarehouse();
    }

    @Test
    @DisplayName(" Récupérer un inventaire par ID")
    void testFindById() {
        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);
        var result = inventoryService.findById(1L);
        assertTrue(result.isPresent());
        assertEquals(testInventoryDTO, result.get());
        verify(inventoryRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName(" Récupérer les inventaires par entrepôt")
    void testFindByWarehouseId() {
        when(inventoryRepository.findByWarehouseId(1L)).thenReturn(List.of(testInventory));
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);
        var result = inventoryService.findByWarehouseId(1L);
        assertNotNull(result);
        assertEquals(1, result.size());
        verify(inventoryRepository, times(1)).findByWarehouseId(1L);
    }

    @Test
    @DisplayName(" Créer un nouvel inventaire")
    void testSaveInventory() {
        // FIX: Add mock for productRepository to avoid "Product non trouve avec lid" error
        when(warehouseRepository.findById(1L)).thenReturn(Optional.of(testWarehouse));
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(inventoryMapper.toEntity(testInventoryDTO)).thenReturn(testInventory);
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(testInventory);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);

        var result = inventoryService.save(testInventoryDTO);

        assertNotNull(result);
        verify(warehouseRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).findById(1L); // Added verification
        verify(inventoryRepository, times(1)).save(any(Inventory.class));
    }

    @Test
    @DisplayName("Erreur - Entrepôt introuvable lors de la création")
    void testSaveInventoryWarehouseNotFound() {
        when(warehouseRepository.findById(999L)).thenReturn(Optional.empty());

        InventoryDTO dto = InventoryDTO.builder().warehouseId(999L).build();
        assertThrows(RuntimeException.class, () ->
                inventoryService.save(dto)
        );

        verify(inventoryRepository, never()).save(any());
    }

    @Test
    @DisplayName(" Mettre à jour un inventaire")
    void testUpdateInventory() {
        InventoryDTO updateDTO = InventoryDTO.builder()
                .qtyOnHand(150)
                .qtyReserved(30)
                .warehouseId(1L)
                .build();

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(warehouseRepository.findById(1L)).thenReturn(Optional.of(testWarehouse));
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(testInventory);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);
        var result = inventoryService.update(1L, updateDTO);
        assertNotNull(result);
        verify(inventoryRepository, times(1)).findById(1L);
        verify(inventoryRepository, times(1)).save(any(Inventory.class));
    }

    @Test
    @DisplayName(" Erreur - Inventaire introuvable lors de la mise à jour")
    void testUpdateInventoryNotFound() {
        when(inventoryRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () ->
                inventoryService.update(999L, testInventoryDTO)
        );

        verify(inventoryRepository, never()).save(any());
    }

    @Test
    @DisplayName(" Mettre à jour les quantités")
    void testUpdateQuantities() {
        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(testInventory);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);
        var result = inventoryService.updateQuantities(1L, 200, 50);
        assertNotNull(result);
        verify(inventoryRepository, times(1)).findById(1L);
        verify(inventoryRepository, times(1)).save(any(Inventory.class));
    }

    @Test
    @DisplayName(" Erreur - Inventaire introuvable lors de la mise à jour des quantités")
    void testUpdateQuantitiesNotFound() {
        when(inventoryRepository.findById(999L)).thenReturn(Optional.empty());
        assertThrows(RuntimeException.class, () ->
                inventoryService.updateQuantities(999L, 100, 20)
        );
    }

    @Test
    @DisplayName(" Supprimer un inventaire")
    void testDeleteInventory() {
        testInventory.setQtyReserved(0);
        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        inventoryService.delete(1L);
        verify(inventoryRepository, times(1)).findById(1L);
        verify(inventoryRepository, times(1)).deleteById(1L);
    }

    @Test
    @DisplayName(" Erreur - Ne pas supprimer un inventaire avec stock réservé")
    void testDeleteInventoryWithReservedStock() {
        testInventory.setQtyReserved(20);
        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        assertThrows(RuntimeException.class, () ->
                inventoryService.delete(1L)
        );

        verify(inventoryRepository, never()).deleteById(anyLong());
    }

    @Test
    @DisplayName(" Erreur - Inventaire introuvable lors de la suppression")
    void testDeleteInventoryNotFound() {
        when(inventoryRepository.findById(999L)).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () ->
                inventoryService.delete(999L)
        );

        verify(inventoryRepository, never()).deleteById(anyLong());
    }

    @Test
    @DisplayName(" Récupérer les inventaires vides")
    void testFindAllEmpty() {
        when(inventoryRepository.findAllWithWarehouse()).thenReturn(List.of());
        var result = inventoryService.findAll();

        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(inventoryRepository, times(1)).findAllWithWarehouse();
    }

    @Test
    @DisplayName(" Récupérer les inventaires par entrepôt vides")
    void testFindByWarehouseIdEmpty() {
        when(inventoryRepository.findByWarehouseId(1L)).thenReturn(List.of());
        var result = inventoryService.findByWarehouseId(1L);
        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(inventoryRepository, times(1)).findByWarehouseId(1L);
    }

    @Test
    @DisplayName(" Créer un inventaire avec quantités par défaut")
    void testSaveInventoryDefaultQuantities() {
        InventoryDTO dto = InventoryDTO.builder()
                .warehouseId(1L)
                .productId(1L)
                .qtyOnHand(null)
                .qtyReserved(null)
                .build();

        Inventory inventory = new Inventory();
        inventory.setId(1L);
        inventory.setWarehouse(testWarehouse);
        inventory.setProduct(testProduct);
        inventory.setQtyOnHand(0);
        inventory.setQtyReserved(0);

        when(warehouseRepository.findById(1L)).thenReturn(Optional.of(testWarehouse));
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(inventoryMapper.toEntity(dto)).thenReturn(inventory);
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(inventory);
        when(inventoryMapper.toDto(inventory)).thenReturn(testInventoryDTO);

        var result = inventoryService.save(dto);

        assertNotNull(result);
        verify(warehouseRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).findById(1L); // Added verification
        verify(inventoryRepository, times(1)).save(any(Inventory.class));
    }
}