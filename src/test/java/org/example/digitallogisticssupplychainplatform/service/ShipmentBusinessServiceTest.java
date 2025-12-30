package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.entity.Carrier;
import org.example.digitallogisticssupplychainplatform.entity.Shipment;
import org.example.digitallogisticssupplychainplatform.entity.ShipmentStatus;
import org.example.digitallogisticssupplychainplatform.exception.BusinessException;
import org.example.digitallogisticssupplychainplatform.exception.ResourceNotFoundException;
import org.example.digitallogisticssupplychainplatform.repository.CarrierRepository;
import org.example.digitallogisticssupplychainplatform.repository.ShipmentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - ShipmentBusinessService")
class ShipmentBusinessServiceTest {

    @Mock
    private ShipmentRepository shipmentRepository;

    @Mock
    private CarrierRepository carrierRepository;

    private ShipmentBusinessService shipmentBusinessService;

    private Carrier testCarrier;
    private Shipment testShipment;

    @BeforeEach
    void setUp() {
        shipmentBusinessService = new ShipmentBusinessService(
                shipmentRepository,
                carrierRepository
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
    }

    // ============================================================
    // TEST: updateStatus - PLANNED to IN_TRANSIT
    // ============================================================

    @Test
    @DisplayName("✓ updateStatus - Transition PLANNED → IN_TRANSIT")
    void testUpdateStatusPlannedToInTransit() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(shipmentRepository.save(any(Shipment.class))).thenReturn(testShipment);

        shipmentBusinessService.updateStatus(1L, ShipmentStatus.IN_TRANSIT);

        assertEquals(ShipmentStatus.IN_TRANSIT, testShipment.getStatus());
        assertNotNull(testShipment.getShippedDate());
        verify(shipmentRepository, times(1)).findById(1L);
        verify(shipmentRepository, times(1)).save(any(Shipment.class));
    }

    @Test
    @DisplayName("✓ updateStatus - Transition PLANNED → CANCELLED")
    void testUpdateStatusPlannedToCancelled() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(shipmentRepository.save(any(Shipment.class))).thenReturn(testShipment);

        shipmentBusinessService.updateStatus(1L, ShipmentStatus.CANCELLED);

        assertEquals(ShipmentStatus.CANCELLED, testShipment.getStatus());
        verify(shipmentRepository, times(1)).findById(1L);
        verify(shipmentRepository, times(1)).save(any(Shipment.class));
    }

    @Test
    @DisplayName("✓ updateStatus - Transition IN_TRANSIT → DELIVERED")
    void testUpdateStatusInTransitToDelivered() {
        testShipment.setStatus(ShipmentStatus.IN_TRANSIT);
        testShipment.setShippedDate(LocalDateTime.now());

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(shipmentRepository.save(any(Shipment.class))).thenReturn(testShipment);

        shipmentBusinessService.updateStatus(1L, ShipmentStatus.DELIVERED);

        assertEquals(ShipmentStatus.DELIVERED, testShipment.getStatus());
        assertNotNull(testShipment.getDeliveredDate());
        verify(shipmentRepository, times(1)).findById(1L);
        verify(shipmentRepository, times(1)).save(any(Shipment.class));
    }

    @Test
    @DisplayName("❌ updateStatus - Transition invalide PLANNED → DELIVERED")
    void testUpdateStatusInvalidTransitionPlannedToDelivered() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));

        assertThrows(BusinessException.class, () ->
                shipmentBusinessService.updateStatus(1L, ShipmentStatus.DELIVERED));

        verify(shipmentRepository, times(1)).findById(1L);
        verify(shipmentRepository, never()).save(any());
    }

    @Test
    @DisplayName("❌ updateStatus - Transition invalide IN_TRANSIT → PLANNED")
    void testUpdateStatusInvalidTransitionInTransitToPlanned() {
        testShipment.setStatus(ShipmentStatus.IN_TRANSIT);

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));

        assertThrows(BusinessException.class, () ->
                shipmentBusinessService.updateStatus(1L, ShipmentStatus.PLANNED));

        verify(shipmentRepository, times(1)).findById(1L);
        verify(shipmentRepository, never()).save(any());
    }

    @Test
    @DisplayName("❌ updateStatus - Transition invalide DELIVERED → IN_TRANSIT")
    void testUpdateStatusInvalidTransitionDeliveredToInTransit() {
        testShipment.setStatus(ShipmentStatus.DELIVERED);

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));

        assertThrows(BusinessException.class, () ->
                shipmentBusinessService.updateStatus(1L, ShipmentStatus.IN_TRANSIT));

        verify(shipmentRepository, times(1)).findById(1L);
        verify(shipmentRepository, never()).save(any());
    }

    @Test
    @DisplayName("❌ updateStatus - Transition invalide CANCELLED → PLANNED")
    void testUpdateStatusInvalidTransitionCancelledToPlanned() {
        testShipment.setStatus(ShipmentStatus.CANCELLED);

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));

        assertThrows(BusinessException.class, () ->
                shipmentBusinessService.updateStatus(1L, ShipmentStatus.PLANNED));

        verify(shipmentRepository, times(1)).findById(1L);
        verify(shipmentRepository, never()).save(any());
    }

    @Test
    @DisplayName("❌ updateStatus - Expédition non trouvée")
    void testUpdateStatusNotFound() {
        when(shipmentRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                shipmentBusinessService.updateStatus(999L, ShipmentStatus.IN_TRANSIT));

        verify(shipmentRepository, times(1)).findById(999L);
        verify(shipmentRepository, never()).save(any());
    }

    // ============================================================
    // TEST: trackShipment
    // ============================================================

    @Test
    @DisplayName("✓ trackShipment - Suivre expédition PLANNED")
    void testTrackShipmentPlanned() {
        when(shipmentRepository.findByTrackingNumber("TRACK-001")).thenReturn(Optional.of(testShipment));

        ShipmentBusinessService.ShipmentTracking result = shipmentBusinessService.trackShipment("TRACK-001");

        assertNotNull(result);
        assertEquals("TRACK-001", result.getTrackingNumber());
        assertEquals("Carrier 1", result.getCarrierName());
        assertEquals(ShipmentStatus.PLANNED, result.getStatus());
        assertNotNull(result.getPlannedDate());
        assertNull(result.getShippedDate());
        assertNull(result.getDeliveredDate());
        verify(shipmentRepository, times(1)).findByTrackingNumber("TRACK-001");
    }

    @Test
    @DisplayName("✓ trackShipment - Suivre expédition IN_TRANSIT")
    void testTrackShipmentInTransit() {
        testShipment.setStatus(ShipmentStatus.IN_TRANSIT);
        testShipment.setShippedDate(LocalDateTime.now());

        when(shipmentRepository.findByTrackingNumber("TRACK-001")).thenReturn(Optional.of(testShipment));

        ShipmentBusinessService.ShipmentTracking result = shipmentBusinessService.trackShipment("TRACK-001");

        assertNotNull(result);
        assertEquals(ShipmentStatus.IN_TRANSIT, result.getStatus());
        assertNotNull(result.getShippedDate());
        assertNull(result.getDeliveredDate());
        verify(shipmentRepository, times(1)).findByTrackingNumber("TRACK-001");
    }

    @Test
    @DisplayName("✓ trackShipment - Suivre expédition DELIVERED")
    void testTrackShipmentDelivered() {
        testShipment.setStatus(ShipmentStatus.DELIVERED);
        testShipment.setShippedDate(LocalDateTime.now().minusHours(5));
        testShipment.setDeliveredDate(LocalDateTime.now());

        when(shipmentRepository.findByTrackingNumber("TRACK-001")).thenReturn(Optional.of(testShipment));

        ShipmentBusinessService.ShipmentTracking result = shipmentBusinessService.trackShipment("TRACK-001");

        assertNotNull(result);
        assertEquals(ShipmentStatus.DELIVERED, result.getStatus());
        assertNotNull(result.getShippedDate());
        assertNotNull(result.getDeliveredDate());
        verify(shipmentRepository, times(1)).findByTrackingNumber("TRACK-001");
    }

    @Test
    @DisplayName("❌ trackShipment - Tracking non trouvé")
    void testTrackShipmentNotFound() {
        when(shipmentRepository.findByTrackingNumber("INVALID")).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                shipmentBusinessService.trackShipment("INVALID"));

        verify(shipmentRepository, times(1)).findByTrackingNumber("INVALID");
    }

    // ============================================================
    // TEST: validateTransition
    // ============================================================

    @Test
    @DisplayName("✓ Transitions valides - Tous les cas")
    void testAllValidTransitions() {
        // PLANNED → IN_TRANSIT
        testShipment.setStatus(ShipmentStatus.PLANNED);
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(shipmentRepository.save(any())).thenReturn(testShipment);
        assertDoesNotThrow(() -> shipmentBusinessService.updateStatus(1L, ShipmentStatus.IN_TRANSIT));

        // PLANNED → CANCELLED
        testShipment.setStatus(ShipmentStatus.PLANNED);
        assertDoesNotThrow(() -> shipmentBusinessService.updateStatus(1L, ShipmentStatus.CANCELLED));

        // IN_TRANSIT → DELIVERED
        testShipment.setStatus(ShipmentStatus.IN_TRANSIT);
        assertDoesNotThrow(() -> shipmentBusinessService.updateStatus(1L, ShipmentStatus.DELIVERED));
    }

    // ============================================================
    // TEST: Multiple operations
    // ============================================================

    @Test
    @DisplayName("✓ Opérations multiples - Créer et tracker")
    void testCreateAndTrack() {
        // Create
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(shipmentRepository.save(any())).thenReturn(testShipment);
        shipmentBusinessService.updateStatus(1L, ShipmentStatus.IN_TRANSIT);

        // Track
        when(shipmentRepository.findByTrackingNumber("TRACK-001")).thenReturn(Optional.of(testShipment));
        ShipmentBusinessService.ShipmentTracking tracking = shipmentBusinessService.trackShipment("TRACK-001");

        assertNotNull(tracking);
        assertEquals("TRACK-001", tracking.getTrackingNumber());
        verify(shipmentRepository, times(1)).findById(1L);
        verify(shipmentRepository, times(1)).findByTrackingNumber("TRACK-001");
    }

    @Test
    @DisplayName("✓ Opérations multiples - Transition complète")
    void testCompleteTransition() {
        // PLANNED → IN_TRANSIT
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(testShipment));
        when(shipmentRepository.save(any())).thenReturn(testShipment);
        shipmentBusinessService.updateStatus(1L, ShipmentStatus.IN_TRANSIT);
        assertEquals(ShipmentStatus.IN_TRANSIT, testShipment.getStatus());

        // IN_TRANSIT → DELIVERED
        testShipment.setStatus(ShipmentStatus.IN_TRANSIT);
        shipmentBusinessService.updateStatus(1L, ShipmentStatus.DELIVERED);
        assertEquals(ShipmentStatus.DELIVERED, testShipment.getStatus());

        verify(shipmentRepository, times(2)).findById(1L);
        verify(shipmentRepository, times(2)).save(any());
    }

    @Test
    @DisplayName("✓ Opérations multiples - Track à chaque étape")
    void testTrackAtEachStep() {
        // Track at PLANNED
        when(shipmentRepository.findByTrackingNumber("TRACK-001")).thenReturn(Optional.of(testShipment));
        ShipmentBusinessService.ShipmentTracking tracking1 = shipmentBusinessService.trackShipment("TRACK-001");
        assertEquals(ShipmentStatus.PLANNED, tracking1.getStatus());

        // Transition to IN_TRANSIT
        testShipment.setStatus(ShipmentStatus.IN_TRANSIT);
        testShipment.setShippedDate(LocalDateTime.now());

        // Track at IN_TRANSIT
        ShipmentBusinessService.ShipmentTracking tracking2 = shipmentBusinessService.trackShipment("TRACK-001");
        assertEquals(ShipmentStatus.IN_TRANSIT, tracking2.getStatus());
        assertNotNull(tracking2.getShippedDate());

        verify(shipmentRepository, times(2)).findByTrackingNumber("TRACK-001");
    }
}