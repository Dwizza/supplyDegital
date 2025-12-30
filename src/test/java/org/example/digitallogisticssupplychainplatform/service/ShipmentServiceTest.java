package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.ShipmentCreateDTO;
import org.example.digitallogisticssupplychainplatform.dto.ShipmentDTO;
import org.example.digitallogisticssupplychainplatform.dto.ShipmentUpdateDTO;
import org.example.digitallogisticssupplychainplatform.entity.Carrier;
import org.example.digitallogisticssupplychainplatform.entity.Shipment;
import org.example.digitallogisticssupplychainplatform.entity.ShipmentStatus;
import org.example.digitallogisticssupplychainplatform.exception.DuplicateResourceException;
import org.example.digitallogisticssupplychainplatform.exception.ResourceNotFoundException;
import org.example.digitallogisticssupplychainplatform.mapper.ShipmentMapper;
import org.example.digitallogisticssupplychainplatform.repository.CarrierRepository;
import org.example.digitallogisticssupplychainplatform.repository.ShipmentRepository;
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
@DisplayName("Tests - ShipmentService")
class ShipmentServiceTest {

    @Mock
    private ShipmentRepository shipmentRepository;

    @Mock
    private CarrierRepository carrierRepository;

    @Mock
    private ShipmentMapper shipmentMapper;

    private ShipmentService shipmentService;

    private Carrier testCarrier;
    private Shipment testShipment;
    private ShipmentDTO testShipmentDTO;

    @BeforeEach
    void setUp() {
        shipmentService = new ShipmentService(
                shipmentRepository,
                carrierRepository,
                shipmentMapper
        );

        testCarrier = new Carrier();
        testCarrier.setId(1L);
        testCarrier.setName("Carrier 1");

        testShipment = new Shipment();
        testShipment.setId(1L);
        testShipment.setTrackingNumber("TRACK-001");
        testShipment.setCarrier(testCarrier);
        testShipment.setStatus(ShipmentStatus.PLANNED);
        testShipment.setPlannedDate(LocalDateTime.now().plusDays(1));
        testShipment.setDescription("Test shipment");

        testShipmentDTO = new ShipmentDTO();
        testShipmentDTO.setId(1L);
        testShipmentDTO.setTrackingNumber("TRACK-001");
        testShipmentDTO.setCarrierId(1L);
        testShipmentDTO.setCarrierName("Carrier 1");
        testShipmentDTO.setStatus("PLANNED");
        testShipmentDTO.setPlannedDate(LocalDateTime.now().plusDays(1));
    }

    // ============================================================
    // TEST: findAll
    // ============================================================

    @Test
    @DisplayName("✓ findAll - Récupérer toutes les expéditions")
    void testFindAll() {
        List<Shipment> shipments = new ArrayList<>();
        shipments.add(testShipment);

        when(shipmentRepository.findAll()).thenReturn(shipments);
        when(shipmentMapper.toDTO(testShipment)).thenReturn(testShipmentDTO);

        List<ShipmentDTO> result = shipmentService.findAll();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(shipmentRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ findAll - Liste vide")
    void testFindAllEmpty() {
        when(shipmentRepository.findAll()).thenReturn(new ArrayList<>());

        List<ShipmentDTO> result = shipmentService.findAll();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(shipmentRepository, times(1)).findAll();
    }

    // ============================================================
    // TEST: findById
    // ============================================================

    @Test
    @DisplayName("✓ findById - Récupérer expédition par ID")
    void testFindById() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(shipmentMapper.toDTO(testShipment)).thenReturn(testShipmentDTO);

        ShipmentDTO result = shipmentService.findById(1L);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(shipmentRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("❌ findById - Expédition non trouvée")
    void testFindByIdNotFound() {
        when(shipmentRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> shipmentService.findById(999L));
        verify(shipmentRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: findByCarrierId
    // ============================================================

    @Test
    @DisplayName("✓ findByCarrierId - Récupérer par transporteur")
    void testFindByCarrierId() {
        List<Shipment> shipments = new ArrayList<>();
        shipments.add(testShipment);

        when(shipmentRepository.findByCarrierId(1L)).thenReturn(shipments);
        when(shipmentMapper.toDTO(testShipment)).thenReturn(testShipmentDTO);

        List<ShipmentDTO> result = shipmentService.findByCarrierId(1L);

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(shipmentRepository, times(1)).findByCarrierId(1L);
    }

    @Test
    @DisplayName("✓ findByCarrierId - Transporteur sans expéditions")
    void testFindByCarrierIdEmpty() {
        when(shipmentRepository.findByCarrierId(999L)).thenReturn(new ArrayList<>());

        List<ShipmentDTO> result = shipmentService.findByCarrierId(999L);

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(shipmentRepository, times(1)).findByCarrierId(999L);
    }

    // ============================================================
    // TEST: findByStatus
    // ============================================================

    @Test
    @DisplayName("✓ findByStatus - Récupérer par statut PLANNED")
    void testFindByStatusPlanned() {
        List<Shipment> shipments = new ArrayList<>();
        shipments.add(testShipment);

        when(shipmentRepository.findByStatus(ShipmentStatus.PLANNED)).thenReturn(shipments);
        when(shipmentMapper.toDTO(testShipment)).thenReturn(testShipmentDTO);

        List<ShipmentDTO> result = shipmentService.findByStatus("PLANNED");

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(shipmentRepository, times(1)).findByStatus(ShipmentStatus.PLANNED);
    }

    @Test
    @DisplayName("✓ findByStatus - Récupérer par statut IN_TRANSIT")
    void testFindByStatusInTransit() {
        List<Shipment> shipments = new ArrayList<>();

        when(shipmentRepository.findByStatus(ShipmentStatus.IN_TRANSIT)).thenReturn(shipments);

        List<ShipmentDTO> result = shipmentService.findByStatus("IN_TRANSIT");

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(shipmentRepository, times(1)).findByStatus(ShipmentStatus.IN_TRANSIT);
    }

    // ============================================================
    // TEST: findByTrackingNumber
    // ============================================================

    @Test
    @DisplayName("✓ findByTrackingNumber - Récupérer par tracking")
    void testFindByTrackingNumber() {
        when(shipmentRepository.findByTrackingNumber("TRACK-001")).thenReturn(Optional.of(testShipment));
        when(shipmentMapper.toDTO(testShipment)).thenReturn(testShipmentDTO);

        ShipmentDTO result = shipmentService.findByTrackingNumber("TRACK-001");

        assertNotNull(result);
        assertEquals("TRACK-001", result.getTrackingNumber());
        verify(shipmentRepository, times(1)).findByTrackingNumber("TRACK-001");
    }

    @Test
    @DisplayName("❌ findByTrackingNumber - Tracking non trouvé")
    void testFindByTrackingNumberNotFound() {
        when(shipmentRepository.findByTrackingNumber("INVALID")).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> shipmentService.findByTrackingNumber("INVALID"));
        verify(shipmentRepository, times(1)).findByTrackingNumber("INVALID");
    }

    // ============================================================
    // TEST: create
    // ============================================================

    @Test
    @DisplayName("✓ create - Créer une expédition")
    void testCreateSuccess() {
        ShipmentCreateDTO createDTO = new ShipmentCreateDTO();
        createDTO.setTrackingNumber("TRACK-002");
        createDTO.setCarrierId(1L);
        createDTO.setPlannedDate(LocalDateTime.now().plusDays(1));
        createDTO.setStatus("PLANNED");
        createDTO.setDescription("New shipment");

        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        when(shipmentRepository.existsByTrackingNumber("TRACK-002")).thenReturn(false);
        when(shipmentMapper.toEntity(createDTO, testCarrier)).thenReturn(testShipment);
        when(shipmentRepository.save(any(Shipment.class))).thenReturn(testShipment);
        when(shipmentMapper.toDTO(testShipment)).thenReturn(testShipmentDTO);

        ShipmentDTO result = shipmentService.create(createDTO);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(carrierRepository, times(1)).findById(1L);
        verify(shipmentRepository, times(1)).save(any(Shipment.class));
    }

    @Test
    @DisplayName("❌ create - Transporteur non trouvé")
    void testCreateCarrierNotFound() {
        ShipmentCreateDTO createDTO = new ShipmentCreateDTO();
        createDTO.setCarrierId(999L);

        when(carrierRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> shipmentService.create(createDTO));
        verify(carrierRepository, times(1)).findById(999L);
    }

    @Test
    @DisplayName("❌ create - Numéro de suivi dupliqué")
    void testCreateDuplicateTracking() {
        ShipmentCreateDTO createDTO = new ShipmentCreateDTO();
        createDTO.setTrackingNumber("TRACK-001");
        createDTO.setCarrierId(1L);

        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        when(shipmentRepository.existsByTrackingNumber("TRACK-001")).thenReturn(true);

        assertThrows(DuplicateResourceException.class, () -> shipmentService.create(createDTO));
        verify(shipmentRepository, times(1)).existsByTrackingNumber("TRACK-001");
        verify(shipmentRepository, never()).save(any());
    }

    // ============================================================
    // TEST: update
    // ============================================================

    @Test
    @DisplayName("✓ update - Mettre à jour expédition")
    void testUpdateSuccess() {
        ShipmentUpdateDTO updateDTO = new ShipmentUpdateDTO();
        updateDTO.setDescription("Updated description");

        Shipment updatedShipment = new Shipment();
        updatedShipment.setId(1L);
        updatedShipment.setDescription("Updated description");

        ShipmentDTO updatedDTO = new ShipmentDTO();
        updatedDTO.setId(1L);
        updatedDTO.setDescription("Updated description");

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(shipmentRepository.save(any(Shipment.class))).thenReturn(updatedShipment);
        when(shipmentMapper.toDTO(updatedShipment)).thenReturn(updatedDTO);

        ShipmentDTO result = shipmentService.update(1L, updateDTO);

        assertNotNull(result);
        assertEquals("Updated description", result.getDescription());
        verify(shipmentRepository, times(1)).findById(1L);
        verify(shipmentRepository, times(1)).save(any(Shipment.class));
    }

    @Test
    @DisplayName("❌ update - Expédition non trouvée")
    void testUpdateNotFound() {
        ShipmentUpdateDTO updateDTO = new ShipmentUpdateDTO();

        when(shipmentRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> shipmentService.update(999L, updateDTO));
        verify(shipmentRepository, times(1)).findById(999L);
    }

    @Test
    @DisplayName("❌ update - Nouveau tracking dupliqué")
    void testUpdateDuplicateTracking() {
        ShipmentUpdateDTO updateDTO = new ShipmentUpdateDTO();
        updateDTO.setTrackingNumber("TRACK-999");

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(shipmentRepository.existsByTrackingNumber("TRACK-999")).thenReturn(true);

        assertThrows(DuplicateResourceException.class, () -> shipmentService.update(1L, updateDTO));
        verify(shipmentRepository, never()).save(any());
    }

    @Test
    @DisplayName("✓ update - Mettre à jour avec nouveau transporteur")
    void testUpdateWithNewCarrier() {
        Carrier newCarrier = new Carrier();
        newCarrier.setId(2L);

        ShipmentUpdateDTO updateDTO = new ShipmentUpdateDTO();
        updateDTO.setCarrierId(2L);

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(carrierRepository.findById(2L)).thenReturn(Optional.of(newCarrier));
        when(shipmentRepository.save(any(Shipment.class))).thenReturn(testShipment);
        when(shipmentMapper.toDTO(testShipment)).thenReturn(testShipmentDTO);

        ShipmentDTO result = shipmentService.update(1L, updateDTO);

        assertNotNull(result);
        verify(carrierRepository, times(1)).findById(2L);
        verify(shipmentRepository, times(1)).save(any(Shipment.class));
    }

    // ============================================================
    // TEST: delete
    // ============================================================

    @Test
    @DisplayName("✓ delete - Supprimer expédition")
    void testDeleteSuccess() {
        when(shipmentRepository.existsById(1L)).thenReturn(true);
        doNothing().when(shipmentRepository).deleteById(1L);

        shipmentService.delete(1L);

        verify(shipmentRepository, times(1)).existsById(1L);
        verify(shipmentRepository, times(1)).deleteById(1L);
    }

    @Test
    @DisplayName("❌ delete - Expédition non trouvée")
    void testDeleteNotFound() {
        when(shipmentRepository.existsById(999L)).thenReturn(false);

        assertThrows(ResourceNotFoundException.class, () -> shipmentService.delete(999L));
        verify(shipmentRepository, times(1)).existsById(999L);
        verify(shipmentRepository, never()).deleteById(anyLong());
    }

    // ============================================================
    // TEST: Multiple operations
    // ============================================================

    @Test
    @DisplayName("✓ Opérations multiples - Créer et récupérer")
    void testCreateAndGet() {
        ShipmentCreateDTO createDTO = new ShipmentCreateDTO();
        createDTO.setTrackingNumber("TRACK-003");
        createDTO.setCarrierId(1L);

        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        when(shipmentRepository.existsByTrackingNumber("TRACK-003")).thenReturn(false);
        when(shipmentMapper.toEntity(any(), any())).thenReturn(testShipment);
        when(shipmentRepository.save(any())).thenReturn(testShipment);
        when(shipmentMapper.toDTO(testShipment)).thenReturn(testShipmentDTO);

        ShipmentDTO created = shipmentService.create(createDTO);
        assertNotNull(created);

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        ShipmentDTO retrieved = shipmentService.findById(1L);
        assertNotNull(retrieved);
        assertEquals(created.getId(), retrieved.getId());
    }

    @Test
    @DisplayName("✓ Opérations multiples - Créer et mettre à jour")
    void testCreateAndUpdate() {
        ShipmentCreateDTO createDTO = new ShipmentCreateDTO();
        createDTO.setTrackingNumber("TRACK-004");
        createDTO.setCarrierId(1L);

        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        when(shipmentRepository.existsByTrackingNumber("TRACK-004")).thenReturn(false);
        when(shipmentMapper.toEntity(any(), any())).thenReturn(testShipment);
        when(shipmentRepository.save(any())).thenReturn(testShipment);
        when(shipmentMapper.toDTO(testShipment)).thenReturn(testShipmentDTO);

        ShipmentDTO created = shipmentService.create(createDTO);
        assertNotNull(created);

        ShipmentUpdateDTO updateDTO = new ShipmentUpdateDTO();
        updateDTO.setDescription("Updated");

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        ShipmentDTO updated = shipmentService.update(1L, updateDTO);
        assertNotNull(updated);
    }
}