package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.InventoryMovementDTO;
import org.example.digitallogisticssupplychainplatform.entity.Inventory;
import org.example.digitallogisticssupplychainplatform.entity.InventoryMovement;
import org.example.digitallogisticssupplychainplatform.entity.MovementType;
import org.example.digitallogisticssupplychainplatform.mapper.InventoryMovementMapper;
import org.example.digitallogisticssupplychainplatform.repository.InventoryMovementRepository;
import org.example.digitallogisticssupplychainplatform.repository.InventoryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - InventoryMovementServiceImpl")
class InventoryMovementServiceImplTest {

    @Mock
    private InventoryMovementRepository movementRepository;

    @Mock
    private InventoryRepository inventoryRepository;

    @Mock
    private InventoryMovementMapper movementMapper;

    @InjectMocks
    private InventoryMovementServiceImpl inventoryMovementService;

    private InventoryMovementDTO testMovementDTO;
    private InventoryMovement testMovement;
    private Inventory testInventory;

    @BeforeEach
    void setUp() {
        testInventory = new Inventory();
        testInventory.setId(1L);

        testMovement = new InventoryMovement();
        testMovement.setId(1L);
        testMovement.setInventory(testInventory);
        testMovement.setType(MovementType.INBOUND);
        testMovement.setQuantity(10);
        testMovement.setOccurredAt(LocalDateTime.now());

        testMovementDTO = new InventoryMovementDTO();
        testMovementDTO.setId(1L);
        testMovementDTO.setInventoryId(1L);
        testMovementDTO.setType("IN");
        testMovementDTO.setQuantity(10);
        testMovementDTO.setOccurredAt(LocalDateTime.now());
    }

    // ============================================================
    // TEST: findAll
    // ============================================================

    @Test
    @DisplayName(" findAll - Récupérer tous les mouvements")
    void testFindAll() {
        List<InventoryMovement> movements = new ArrayList<>();
        movements.add(testMovement);

        when(movementRepository.findAllWithDetails()).thenReturn(movements);
        when(movementMapper.toDto(any(InventoryMovement.class))).thenReturn(testMovementDTO);

        List<InventoryMovementDTO> result = inventoryMovementService.findAll();

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(testMovementDTO, result.get(0));
        verify(movementRepository, times(1)).findAllWithDetails();
    }

    @Test
    @DisplayName(" findAll - Liste vide")
    void testFindAllEmpty() {
        when(movementRepository.findAllWithDetails()).thenReturn(new ArrayList<>());

        List<InventoryMovementDTO> result = inventoryMovementService.findAll();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(movementRepository, times(1)).findAllWithDetails();
    }

    // ============================================================
    // TEST: findById
    // ============================================================

    @Test
    @DisplayName(" findById - Récupérer mouvement par ID")
    void testFindById() {
        when(movementRepository.findByIdWithDetails(1L)).thenReturn(testMovement);
        when(movementMapper.toDto(testMovement)).thenReturn(testMovementDTO);

        InventoryMovementDTO result = inventoryMovementService.findById(1L);

        assertNotNull(result);
        assertEquals(testMovementDTO, result);
        verify(movementRepository, times(1)).findByIdWithDetails(1L);
    }

    @Test
    @DisplayName(" findById - Mouvement non trouvé")
    void testFindByIdNotFound() {
        when(movementRepository.findByIdWithDetails(999L)).thenReturn(null);

        assertThrows(RuntimeException.class, () ->
                inventoryMovementService.findById(999L)
        );

        verify(movementRepository, times(1)).findByIdWithDetails(999L);
    }

    // ============================================================
    // TEST: findByInventoryId
    // ============================================================

    @Test
    @DisplayName(" findByInventoryId - Mouvements par inventaire")
    void testFindByInventoryId() {
        List<InventoryMovement> movements = new ArrayList<>();
        movements.add(testMovement);

        when(movementRepository.findByInventoryId(1L)).thenReturn(movements);
        when(movementMapper.toDto(any(InventoryMovement.class))).thenReturn(testMovementDTO);

        List<InventoryMovementDTO> result = inventoryMovementService.findByInventoryId(1L);

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(movementRepository, times(1)).findByInventoryId(1L);
    }

    // ============================================================
    // TEST: findByProductId
    // ============================================================

    @Test
    @DisplayName(" findByProductId - Mouvements par produit")
    void testFindByProductId() {
        List<InventoryMovement> movements = new ArrayList<>();
        movements.add(testMovement);

        when(movementRepository.findByInventoryProductId(1L)).thenReturn(movements);
        when(movementMapper.toDto(any(InventoryMovement.class))).thenReturn(testMovementDTO);

        List<InventoryMovementDTO> result = inventoryMovementService.findByProductId(1L);

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(movementRepository, times(1)).findByInventoryProductId(1L);
    }

    // ============================================================
    // TEST: findByWarehouseId
    // ============================================================

    @Test
    @DisplayName(" findByWarehouseId - Mouvements par entrepôt")
    void testFindByWarehouseId() {
        List<InventoryMovement> movements = new ArrayList<>();
        movements.add(testMovement);

        when(movementRepository.findByInventoryWarehouseId(1L)).thenReturn(movements);
        when(movementMapper.toDto(any(InventoryMovement.class))).thenReturn(testMovementDTO);

        List<InventoryMovementDTO> result = inventoryMovementService.findByWarehouseId(1L);

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(movementRepository, times(1)).findByInventoryWarehouseId(1L);
    }

    // ============================================================
    // TEST: findByType
    // ============================================================

    @Test
    @DisplayName(" findByType - Mouvements par type IN")
    void testFindByTypeIN() {
        List<InventoryMovement> movements = new ArrayList<>();
        movements.add(testMovement);

        when(movementRepository.findByType(MovementType.INBOUND)).thenReturn(movements);
        when(movementMapper.toDto(any(InventoryMovement.class))).thenReturn(testMovementDTO);

        List<InventoryMovementDTO> result = inventoryMovementService.findByType("INBOUND");

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(movementRepository, times(1)).findByType(MovementType.INBOUND);
    }

    @Test
    @DisplayName(" findByType - Mouvements par type OUT")
    void testFindByTypeOUT() {
        List<InventoryMovement> movements = new ArrayList<>();
        movements.add(testMovement);

        when(movementRepository.findByType(MovementType.OUTBOUND)).thenReturn(movements);
        when(movementMapper.toDto(any(InventoryMovement.class))).thenReturn(testMovementDTO);

        List<InventoryMovementDTO> result = inventoryMovementService.findByType("OUTBOUND");

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(movementRepository, times(1)).findByType(MovementType.OUTBOUND);
    }

    // ============================================================
    // TEST: findByDateRange
    // ============================================================

    @Test
    @DisplayName(" findByDateRange - Mouvements par plage de dates")
    void testFindByDateRange() {
        LocalDateTime startDate = LocalDateTime.now().minusDays(7);
        LocalDateTime endDate = LocalDateTime.now();
        List<InventoryMovement> movements = new ArrayList<>();
        movements.add(testMovement);

        when(movementRepository.findByDateRange(startDate, endDate)).thenReturn(movements);
        when(movementMapper.toDto(any(InventoryMovement.class))).thenReturn(testMovementDTO);

        List<InventoryMovementDTO> result = inventoryMovementService.findByDateRange(startDate, endDate);

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(movementRepository, times(1)).findByDateRange(startDate, endDate);
    }

    // ============================================================
    // TEST: createMovement
    // ============================================================

    @Test
    @DisplayName(" createMovement - Créer mouvement avec succès")
    void testCreateMovement() {
        InventoryMovementDTO newMovementDTO = new InventoryMovementDTO();
        newMovementDTO.setInventoryId(1L);
        newMovementDTO.setType("INBOUND");
        newMovementDTO.setQuantity(10);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));
        when(movementMapper.toEntity(any(InventoryMovementDTO.class))).thenReturn(testMovement);
        when(movementRepository.save(any(InventoryMovement.class))).thenReturn(testMovement);
        when(movementMapper.toDto(testMovement)).thenReturn(testMovementDTO);

        InventoryMovementDTO result = inventoryMovementService.createMovement(newMovementDTO);

        assertNotNull(result);
        assertEquals(testMovementDTO, result);
        verify(inventoryRepository, times(1)).findById(1L);
        verify(movementRepository, times(1)).save(any(InventoryMovement.class));
    }

    @Test
    @DisplayName(" createMovement - Inventaire non trouvé")
    void testCreateMovementInventoryNotFound() {
        InventoryMovementDTO newMovementDTO = new InventoryMovementDTO();
        newMovementDTO.setInventoryId(999L);
        newMovementDTO.setType("IN");
        newMovementDTO.setQuantity(10);

        when(inventoryRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () ->
                inventoryMovementService.createMovement(newMovementDTO)
        );

        verify(inventoryRepository, times(1)).findById(999L);
        verify(movementRepository, never()).save(any());
    }

    @Test
    @DisplayName(" createMovement - Quantité négative")
    void testCreateMovementNegativeQuantity() {
        InventoryMovementDTO newMovementDTO = new InventoryMovementDTO();
        newMovementDTO.setInventoryId(1L);
        newMovementDTO.setType("IN");
        newMovementDTO.setQuantity(-5);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));

        assertThrows(RuntimeException.class, () ->
                inventoryMovementService.createMovement(newMovementDTO)
        );

        verify(inventoryRepository, times(1)).findById(1L);
        verify(movementRepository, never()).save(any());
    }

    @Test
    @DisplayName(" createMovement - Quantité zéro")
    void testCreateMovementZeroQuantity() {
        InventoryMovementDTO newMovementDTO = new InventoryMovementDTO();
        newMovementDTO.setInventoryId(1L);
        newMovementDTO.setType("IN");
        newMovementDTO.setQuantity(0);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));

        assertThrows(RuntimeException.class, () ->
                inventoryMovementService.createMovement(newMovementDTO)
        );

        verify(inventoryRepository, times(1)).findById(1L);
        verify(movementRepository, never()).save(any());
    }

    // ============================================================
    // TEST: deleteMovement
    // ============================================================

    @Test
    @DisplayName(" deleteMovement - Supprimer mouvement")
    void testDeleteMovement() {
        when(movementRepository.existsById(1L)).thenReturn(true);
        doNothing().when(movementRepository).deleteById(1L);

        inventoryMovementService.deleteMovement(1L);

        verify(movementRepository, times(1)).existsById(1L);
        verify(movementRepository, times(1)).deleteById(1L);
    }

    @Test
    @DisplayName(" deleteMovement - Mouvement non trouvé")
    void testDeleteMovementNotFound() {
        when(movementRepository.existsById(999L)).thenReturn(false);

        assertThrows(RuntimeException.class, () ->
                inventoryMovementService.deleteMovement(999L)
        );

        verify(movementRepository, times(1)).existsById(999L);
        verify(movementRepository, never()).deleteById(any());
    }

    // ============================================================
    // TEST: Error Handling
    // ============================================================

    @Test
    @DisplayName("Error messages - Mouvement non trouvé")
    void testErrorMessageMovementNotFound() {
        when(movementRepository.findByIdWithDetails(1L)).thenReturn(null);

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                inventoryMovementService.findById(1L)
        );

        assertTrue(exception.getMessage().contains("Mouvement non trouvé"));
    }

    @Test
    @DisplayName("Error messages - Inventaire non trouvé")
    void testErrorMessageInventoryNotFound() {
        InventoryMovementDTO newMovementDTO = new InventoryMovementDTO();
        newMovementDTO.setInventoryId(1L);
        newMovementDTO.setType("IN");
        newMovementDTO.setQuantity(10);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                inventoryMovementService.createMovement(newMovementDTO)
        );

        assertTrue(exception.getMessage().contains("Inventaire non trouvé"));
    }

    @Test
    @DisplayName("Error messages - Quantité positive")
    void testErrorMessageQuantityPositive() {
        InventoryMovementDTO newMovementDTO = new InventoryMovementDTO();
        newMovementDTO.setInventoryId(1L);
        newMovementDTO.setType("IN");
        newMovementDTO.setQuantity(0);

        when(inventoryRepository.findById(1L)).thenReturn(Optional.of(testInventory));

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                inventoryMovementService.createMovement(newMovementDTO)
        );

        assertTrue(exception.getMessage().contains("quantité doit être positive"));
    }
}