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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - InventoryServiceImpl")
class InventoryServiceImplTest {

    @Mock
    private InventoryRepository inventoryRepository;

    @Mock
    private WareHouseRepository warehouseRepository;

    @Mock
    private ProductRepository productRepository;

    @Mock
    private InventoryMapper inventoryMapper;

    private InventoryServiceImpl inventoryService;

    private WareHouse testWarehouse;
    private Product testProduct;
    private Inventory testInventory;
    private InventoryDTO testInventoryDTO;

    @BeforeEach
    void setUp() {
        inventoryService = new InventoryServiceImpl(
                inventoryRepository,
                warehouseRepository,
                productRepository,
                inventoryMapper
        );

        testWarehouse = new WareHouse();
        testWarehouse.setId(1L);
        testWarehouse.setCode("WH-001");
        testWarehouse.setName("Warehouse 1");

        testProduct = new Product();
        testProduct.setId(1L);
        testProduct.setCode("PROD-001");
        testProduct.setName("Product 1");

        testInventory = new Inventory();
        testInventory.setId(1L);
        testInventory.setQtyOnHand(100);
        testInventory.setQtyReserved(20);
        testInventory.setWarehouse(testWarehouse);
        testInventory.setProduct(testProduct);

        testInventoryDTO = new InventoryDTO();
        testInventoryDTO.setId(1L);
        testInventoryDTO.setQtyOnHand(100);
        testInventoryDTO.setQtyReserved(20);
        testInventoryDTO.setWarehouseId(1L);
        testInventoryDTO.setWarehouseCode("WH-001");
        testInventoryDTO.setWarehouseName("Warehouse 1");
        testInventoryDTO.setProductId(1L);
        testInventoryDTO.setProductCode("PROD-001");
        testInventoryDTO.setProductName("Product 1");
    }

    // ============================================================
    // TEST: findAll
    // ============================================================

    @Test
    @DisplayName(" findAll - Récupérer tous les inventaires")
    void testFindAll() {
        List<Inventory> inventories = new ArrayList<>();
        inventories.add(testInventory);

        when(inventoryRepository.findAllWithWarehouse()).thenReturn(inventories);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);

        List<InventoryDTO> result = inventoryService.findAll();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(inventoryRepository, times(1)).findAllWithWarehouse();
        verify(inventoryMapper, times(1)).toDto(testInventory);
    }

    @Test
    @DisplayName(" findAll - Liste vide")
    void testFindAllEmpty() {
        when(inventoryRepository.findAllWithWarehouse()).thenReturn(new ArrayList<>());

        List<InventoryDTO> result = inventoryService.findAll();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(inventoryRepository, times(1)).findAllWithWarehouse();
    }

    @Test
    @DisplayName(" findAll - Plusieurs inventaires")
    void testFindAllMultiple() {
        Inventory inventory2 = new Inventory();
        inventory2.setId(2L);
        inventory2.setQtyOnHand(50);
        inventory2.setQtyReserved(10);

        List<Inventory> inventories = new ArrayList<>();
        inventories.add(testInventory);
        inventories.add(inventory2);

        InventoryDTO dto2 = new InventoryDTO();
        dto2.setId(2L);

        when(inventoryRepository.findAllWithWarehouse()).thenReturn(inventories);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);
        when(inventoryMapper.toDto(inventory2)).thenReturn(dto2);

        List<InventoryDTO> result = inventoryService.findAll();

        assertNotNull(result);
        assertEquals(2, result.size());
        verify(inventoryRepository, times(1)).findAllWithWarehouse();
    }

    // ============================================================
    // TEST: findByWarehouseId
    // ============================================================

    @Test
    @DisplayName(" findByWarehouseId - Récupérer par entrepôt")
    void testFindByWarehouseId() {
        List<Inventory> inventories = new ArrayList<>();
        inventories.add(testInventory);

        when(inventoryRepository.findByWarehouseId(1L)).thenReturn(inventories);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);

        List<InventoryDTO> result = inventoryService.findByWarehouseId(1L);

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(inventoryRepository, times(1)).findByWarehouseId(1L);
    }

    @Test
    @DisplayName(" findByWarehouseId - Entrepôt sans inventaire")
    void testFindByWarehouseIdEmpty() {
        when(inventoryRepository.findByWarehouseId(999L)).thenReturn(new ArrayList<>());

        List<InventoryDTO> result = inventoryService.findByWarehouseId(999L);

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(inventoryRepository, times(1)).findByWarehouseId(999L);
    }

    @Test
    @DisplayName(" findByWarehouseId - Plusieurs inventaires par entrepôt")
    void testFindByWarehouseIdMultiple() {
        Inventory inventory2 = new Inventory();
        inventory2.setId(2L);

        List<Inventory> inventories = new ArrayList<>();
        inventories.add(testInventory);
        inventories.add(inventory2);

        InventoryDTO dto2 = new InventoryDTO();
        dto2.setId(2L);

        when(inventoryRepository.findByWarehouseId(1L)).thenReturn(inventories);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);
        when(inventoryMapper.toDto(inventory2)).thenReturn(dto2);

        List<InventoryDTO> result = inventoryService.findByWarehouseId(1L);

        assertNotNull(result);
        assertEquals(2, result.size());
        verify(inventoryRepository, times(1)).findByWarehouseId(1L);
    }

    // ============================================================
    // TEST: findById
    // ============================================================

    @Test
    @DisplayName(" findById - Récupérer inventaire par ID")
    void testFindById() {
        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);

        Optional<InventoryDTO> result = inventoryService.findById(1L);

        assertTrue(result.isPresent());
        assertEquals(1L, result.get().getId());
        verify(inventoryRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("findById - Inventaire non trouvé")
    void testFindByIdNotFound() {
        when(inventoryRepository.findById(999L)).thenReturn(Optional.empty());

        Optional<InventoryDTO> result = inventoryService.findById(999L);

        assertFalse(result.isPresent());
        verify(inventoryRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: save
    // ============================================================

    @Test
    @DisplayName(" save - Créer un nouvel inventaire")
    void testSaveSuccess() {
        when(warehouseRepository.findById(1L)).thenReturn(Optional.of(testWarehouse));
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(inventoryMapper.toEntity(testInventoryDTO)).thenReturn(testInventory);
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(testInventory);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);

        InventoryDTO result = inventoryService.save(testInventoryDTO);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        assertEquals(100, result.getQtyOnHand());
        verify(warehouseRepository, times(1)).findById(1L);
        verify(productRepository, times(1)).findById(1L);
        verify(inventoryRepository, times(1)).save(any(Inventory.class));
    }

    @Test
    @DisplayName(" save - Entrepôt non trouvé")
    void testSaveWarehouseNotFound() {
        testInventoryDTO.setWarehouseId(999L);

        when(warehouseRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> inventoryService.save(testInventoryDTO));
        verify(warehouseRepository, times(1)).findById(999L);
    }



    @Test
    @DisplayName(" save - Initialiser quantités nulles")
    void testSaveWithNullQuantities() {
        Inventory inventoryWithNull = new Inventory();
        inventoryWithNull.setId(1L);
        inventoryWithNull.setQtyOnHand(null);
        inventoryWithNull.setQtyReserved(null);

        when(warehouseRepository.findById(1L)).thenReturn(Optional.of(testWarehouse));
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(inventoryMapper.toEntity(testInventoryDTO)).thenReturn(inventoryWithNull);
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(inventoryWithNull);
        when(inventoryMapper.toDto(inventoryWithNull)).thenReturn(testInventoryDTO);

        InventoryDTO result = inventoryService.save(testInventoryDTO);

        assertNotNull(result);
        assertEquals(0, inventoryWithNull.getQtyOnHand());
        assertEquals(0, inventoryWithNull.getQtyReserved());
    }

    // ============================================================
    // TEST: update
    // ============================================================

    @Test
    @DisplayName(" update - Mettre à jour inventaire")
    void testUpdateSuccess() {
        InventoryDTO updateDTO = new InventoryDTO();
        updateDTO.setQtyOnHand(150);
        updateDTO.setQtyReserved(30);
        updateDTO.setWarehouseId(1L);

        Inventory updatedInventory = new Inventory();
        updatedInventory.setId(1L);
        updatedInventory.setQtyOnHand(150);
        updatedInventory.setQtyReserved(30);

        InventoryDTO resultDTO = new InventoryDTO();
        resultDTO.setId(1L);
        resultDTO.setQtyOnHand(150);
        resultDTO.setQtyReserved(30);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(warehouseRepository.findById(1L)).thenReturn(Optional.of(testWarehouse));
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(updatedInventory);
        when(inventoryMapper.toDto(updatedInventory)).thenReturn(resultDTO);

        InventoryDTO result = inventoryService.update(1L, updateDTO);

        assertNotNull(result);
        assertEquals(150, result.getQtyOnHand());
        assertEquals(30, result.getQtyReserved());
        verify(inventoryRepository, times(1)).findById(1L);
        verify(inventoryRepository, times(1)).save(any(Inventory.class));
    }

    @Test
    @DisplayName(" update - Inventaire non trouvé")
    void testUpdateNotFound() {
        InventoryDTO updateDTO = new InventoryDTO();
        updateDTO.setQtyOnHand(150);

        when(inventoryRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> inventoryService.update(999L, updateDTO));
        verify(inventoryRepository, times(1)).findById(999L);
    }

    @Test
    @DisplayName(" update - Entrepôt non trouvé")
    void testUpdateWarehouseNotFound() {
        InventoryDTO updateDTO = new InventoryDTO();
        updateDTO.setQtyOnHand(150);
        updateDTO.setWarehouseId(999L);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(warehouseRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> inventoryService.update(1L, updateDTO));
        verify(warehouseRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: delete
    // ============================================================

    @Test
    @DisplayName(" delete - Supprimer inventaire")
    void testDeleteSuccess() {
        testInventory.setQtyReserved(0);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        doNothing().when(inventoryRepository).deleteById(1L);

        inventoryService.delete(1L);

        verify(inventoryRepository, times(1)).findById(1L);
        verify(inventoryRepository, times(1)).deleteById(1L);
    }

    @Test
    @DisplayName(" delete - Inventaire non trouvé")
    void testDeleteNotFound() {
        when(inventoryRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> inventoryService.delete(999L));
        verify(inventoryRepository, times(1)).findById(999L);
        verify(inventoryRepository, never()).deleteById(anyLong());
    }

    @Test
    @DisplayName(" delete - Stock réservé présent")
    void testDeleteWithReservedStock() {
        testInventory.setQtyReserved(20);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));

        assertThrows(RuntimeException.class, () -> inventoryService.delete(1L));
        verify(inventoryRepository, times(1)).findById(1L);
        verify(inventoryRepository, never()).deleteById(1L);
    }

    // ============================================================
    // TEST: updateQuantities
    // ============================================================

    @Test
    @DisplayName(" updateQuantities - Mettre à jour quantités")
    void testUpdateQuantitiesSuccess() {
        Inventory updatedInventory = new Inventory();
        updatedInventory.setId(1L);
        updatedInventory.setQtyOnHand(200);
        updatedInventory.setQtyReserved(40);

        InventoryDTO resultDTO = new InventoryDTO();
        resultDTO.setId(1L);
        resultDTO.setQtyOnHand(200);
        resultDTO.setQtyReserved(40);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(updatedInventory);
        when(inventoryMapper.toDto(updatedInventory)).thenReturn(resultDTO);

        InventoryDTO result = inventoryService.updateQuantities(1L, 200, 40);

        assertNotNull(result);
        assertEquals(200, result.getQtyOnHand());
        assertEquals(40, result.getQtyReserved());
        verify(inventoryRepository, times(1)).findById(1L);
        verify(inventoryRepository, times(1)).save(any(Inventory.class));
    }

    @Test
    @DisplayName(" updateQuantities - Inventaire non trouvé")
    void testUpdateQuantitiesNotFound() {
        when(inventoryRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> inventoryService.updateQuantities(999L, 100, 20));
        verify(inventoryRepository, times(1)).findById(999L);
    }

    @Test
    @DisplayName(" updateQuantities - Mettre à zéro")
    void testUpdateQuantitiesToZero() {
        Inventory updatedInventory = new Inventory();
        updatedInventory.setId(1L);
        updatedInventory.setQtyOnHand(0);
        updatedInventory.setQtyReserved(0);

        InventoryDTO resultDTO = new InventoryDTO();
        resultDTO.setId(1L);
        resultDTO.setQtyOnHand(0);
        resultDTO.setQtyReserved(0);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(updatedInventory);
        when(inventoryMapper.toDto(updatedInventory)).thenReturn(resultDTO);

        InventoryDTO result = inventoryService.updateQuantities(1L, 0, 0);

        assertNotNull(result);
        assertEquals(0, result.getQtyOnHand());
        assertEquals(0, result.getQtyReserved());
    }

    // ============================================================
    // TEST: Multiple operations
    // ============================================================

    @Test
    @DisplayName(" Opérations multiples - Créer et récupérer")
    void testCreateAndGet() {
        when(warehouseRepository.findById(1L)).thenReturn(Optional.of(testWarehouse));
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(inventoryMapper.toEntity(testInventoryDTO)).thenReturn(testInventory);
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(testInventory);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);

        InventoryDTO created = inventoryService.save(testInventoryDTO);
        assertNotNull(created);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        Optional<InventoryDTO> retrieved = inventoryService.findById(1L);
        assertTrue(retrieved.isPresent());
        assertEquals(created.getId(), retrieved.get().getId());
    }

    @Test
    @DisplayName(" Opérations multiples - Créer, mettre à jour et récupérer")
    void testCreateUpdateAndGet() {
        when(warehouseRepository.findById(1L)).thenReturn(Optional.of(testWarehouse));
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(inventoryMapper.toEntity(testInventoryDTO)).thenReturn(testInventory);
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(testInventory);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);

        InventoryDTO created = inventoryService.save(testInventoryDTO);
        assertNotNull(created);

        InventoryDTO updateDTO = new InventoryDTO();
        updateDTO.setQtyOnHand(150);
        updateDTO.setWarehouseId(1L);

        Inventory updatedInventory = new Inventory();
        updatedInventory.setQtyOnHand(150);

        InventoryDTO updatedDTO = new InventoryDTO();
        updatedDTO.setQtyOnHand(150);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(updatedInventory);
        when(inventoryMapper.toDto(updatedInventory)).thenReturn(updatedDTO);

        InventoryDTO updated = inventoryService.update(1L, updateDTO);
        assertNotNull(updated);
        assertEquals(150, updated.getQtyOnHand());
    }

    @Test
    @DisplayName(" Opérations multiples - Créer et mettre à jour quantités")
    void testCreateAndUpdateQuantities() {
        when(warehouseRepository.findById(1L)).thenReturn(Optional.of(testWarehouse));
        when(productRepository.findById(1L)).thenReturn(Optional.of(testProduct));
        when(inventoryMapper.toEntity(testInventoryDTO)).thenReturn(testInventory);
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(testInventory);
        when(inventoryMapper.toDto(testInventory)).thenReturn(testInventoryDTO);

        InventoryDTO created = inventoryService.save(testInventoryDTO);
        assertNotNull(created);

        Inventory updatedInventory = new Inventory();
        updatedInventory.setQtyOnHand(250);
        updatedInventory.setQtyReserved(50);

        InventoryDTO resultDTO = new InventoryDTO();
        resultDTO.setQtyOnHand(250);
        resultDTO.setQtyReserved(50);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(inventoryRepository.save(any(Inventory.class))).thenReturn(updatedInventory);
        when(inventoryMapper.toDto(updatedInventory)).thenReturn(resultDTO);

        InventoryDTO result = inventoryService.updateQuantities(1L, 250, 50);
        assertNotNull(result);
        assertEquals(250, result.getQtyOnHand());
    }
}