package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.CarrierDTO;
import org.example.digitallogisticssupplychainplatform.entity.Carrier;
import org.example.digitallogisticssupplychainplatform.entity.CarrierStatus;
import org.example.digitallogisticssupplychainplatform.mapper.CarrierMapper;
import org.example.digitallogisticssupplychainplatform.repository.CarrierRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - CarrierService")
class CarrierServiceTest {
    @Mock
    private CarrierRepository carrierRepository;

    @Mock
    private CarrierMapper carrierMapper;

    @InjectMocks
    private CarrierService carrierService;

    private CarrierDTO testCarrierDTO;
    private Carrier testCarrier;

    @BeforeEach
    void setUp() {
        testCarrier = new Carrier();
        testCarrier.setId(1L);
        testCarrier.setCode("DHL");
        testCarrier.setName("DHL Express");
        testCarrier.setContactEmail("contact@dhl.com");
        testCarrier.setContactPhone("+1234567890");
        testCarrier.setBaseShippingRate(new BigDecimal("50.00"));
        testCarrier.setMaxDailyCapacity(100);
        testCarrier.setCurrentDailyShipments(50);
        testCarrier.setCutOffTime(LocalTime.of(17, 0));
        testCarrier.setStatus(CarrierStatus.ACTIVE);

        testCarrierDTO = new CarrierDTO();
        testCarrierDTO.setCode("DHL");
        testCarrierDTO.setName("DHL Express");
        testCarrierDTO.setContactEmail("contact@dhl.com");
        testCarrierDTO.setContactPhone("+1234567890");
        testCarrierDTO.setBaseShippingRate(new BigDecimal("50.00"));
        testCarrierDTO.setMaxDailyCapacity(100);
        testCarrierDTO.setCurrentDailyShipments(50);
        testCarrierDTO.setCutOffTime(LocalTime.of(17, 0));
        testCarrierDTO.setStatus(CarrierStatus.ACTIVE);
    }

    // ============================================================
    // TEST: save
    // ============================================================

    @Test
    @DisplayName("✓ save - Créer un nouveau transporteur")
    void testSave() {
        when(carrierMapper.toEntity(testCarrierDTO)).thenReturn(testCarrier);
        when(carrierRepository.save(testCarrier)).thenReturn(testCarrier);
        when(carrierMapper.toDto(testCarrier)).thenReturn(testCarrierDTO);

        CarrierDTO result = carrierService.save(testCarrierDTO);

        assertNotNull(result);
        assertEquals("DHL", result.getCode());
        assertEquals("DHL Express", result.getName());
        verify(carrierMapper, times(1)).toEntity(testCarrierDTO);
        verify(carrierRepository, times(1)).save(testCarrier);
        verify(carrierMapper, times(1)).toDto(testCarrier);
    }

    // ============================================================
    // TEST: findAll
    // ============================================================

    @Test
    @DisplayName("✓ findAll - Récupérer tous les transporteurs")
    void testFindAll() {
        List<Carrier> carriers = new ArrayList<>();
        carriers.add(testCarrier);

        when(carrierRepository.findAll()).thenReturn(carriers);
        when(carrierMapper.toDto(any(Carrier.class))).thenReturn(testCarrierDTO);

        List<CarrierDTO> result = carrierService.findAll();

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("DHL", result.get(0).getCode());
        verify(carrierRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ findAll - Liste vide")
    void testFindAllEmpty() {
        when(carrierRepository.findAll()).thenReturn(new ArrayList<>());

        List<CarrierDTO> result = carrierService.findAll();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(carrierRepository, times(1)).findAll();
    }

    // ============================================================
    // TEST: findById
    // ============================================================

    @Test
    @DisplayName(" findById - Récupérer transporteur par ID")
    void testFindById() {
        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        when(carrierMapper.toDto(testCarrier)).thenReturn(testCarrierDTO);

        CarrierDTO result = carrierService.findById(1L);

        assertNotNull(result);
        assertEquals("DHL", result.getCode());
        verify(carrierRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName(" findById - Transporteur non trouvé")
    void testFindByIdNotFound() {
        when(carrierRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () ->
                carrierService.findById(999L)
        );

        verify(carrierRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: update
    // ============================================================

    @Test
    @DisplayName("update - Mettre à jour transporteur")
    void testUpdate() {
        CarrierDTO updateDTO = new CarrierDTO();
        updateDTO.setCode("FDX");
        updateDTO.setName("FedEx Updated");
        updateDTO.setContactEmail("updated@fedex.com");
        updateDTO.setContactPhone("+9876543210");
        updateDTO.setBaseShippingRate(new BigDecimal("55.00"));
        updateDTO.setMaxDailyCapacity(150);
        updateDTO.setCurrentDailyShipments(75);
        updateDTO.setCutOffTime(LocalTime.of(18, 0));
        updateDTO.setStatus(CarrierStatus.ACTIVE);

        Carrier updatedCarrier = new Carrier();
        updatedCarrier.setId(1L);
        updatedCarrier.setCode("FDX");
        updatedCarrier.setName("FedEx Updated");
        updatedCarrier.setContactEmail("updated@fedex.com");
        updatedCarrier.setContactPhone("+9876543210");
        updatedCarrier.setBaseShippingRate(new BigDecimal("55.00"));
        updatedCarrier.setMaxDailyCapacity(150);
        updatedCarrier.setCurrentDailyShipments(75);
        updatedCarrier.setCutOffTime(LocalTime.of(18, 0));
        updatedCarrier.setStatus(CarrierStatus.ACTIVE);

        CarrierDTO updatedDTO = new CarrierDTO();
        updatedDTO.setCode("FDX");
        updatedDTO.setName("FedEx Updated");

        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        when(carrierRepository.save(any(Carrier.class))).thenReturn(updatedCarrier);
        when(carrierMapper.toDto(updatedCarrier)).thenReturn(updatedDTO);

        CarrierDTO result = carrierService.update(1L, updateDTO);

        assertNotNull(result);
        assertEquals("FDX", result.getCode());
        verify(carrierRepository, times(1)).findById(1L);
        verify(carrierRepository, times(1)).save(any(Carrier.class));
    }

    @Test
    @DisplayName(" update - Transporteur non trouvé")
    void testUpdateNotFound() {
        when(carrierRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () ->
                carrierService.update(999L, testCarrierDTO)
        );

        verify(carrierRepository, times(1)).findById(999L);
        verify(carrierRepository, never()).save(any());
    }

    // ============================================================
    // TEST: delete
    // ============================================================

    @Test
    @DisplayName(" delete - Supprimer transporteur")
    void testDelete() {
        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        doNothing().when(carrierRepository).delete(testCarrier);

        carrierService.delete(1L);

        verify(carrierRepository, times(1)).findById(1L);
        verify(carrierRepository, times(1)).delete(testCarrier);
    }

    @Test
    @DisplayName(" delete - Transporteur non trouvé")
    void testDeleteNotFound() {
        when(carrierRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () ->
                carrierService.delete(999L)
        );

        verify(carrierRepository, times(1)).findById(999L);
        verify(carrierRepository, never()).delete(any());
    }

    // ============================================================
    // TEST: updateStatus
    // ============================================================

    @Test
    @DisplayName(" updateStatus - Changer statut à ACTIVE")
    void testUpdateStatusActive() {
        Carrier statusChangedCarrier = new Carrier();
        statusChangedCarrier.setId(1L);
        statusChangedCarrier.setCode("DHL");
        statusChangedCarrier.setStatus(CarrierStatus.ACTIVE);

        CarrierDTO statusDTO = new CarrierDTO();
        statusDTO.setStatus(CarrierStatus.ACTIVE);

        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        when(carrierRepository.save(any(Carrier.class))).thenReturn(statusChangedCarrier);
        when(carrierMapper.toDto(statusChangedCarrier)).thenReturn(statusDTO);

        CarrierDTO result = carrierService.updateStatus(1L, "ACTIVE");

        assertNotNull(result);
        assertEquals(CarrierStatus.ACTIVE, result.getStatus());
        verify(carrierRepository, times(1)).findById(1L);
        verify(carrierRepository, times(1)).save(any(Carrier.class));
    }

    @Test
    @DisplayName(" updateStatus - Changer statut à INACTIVE")
    void testUpdateStatusInactive() {
        Carrier statusChangedCarrier = new Carrier();
        statusChangedCarrier.setId(1L);
        statusChangedCarrier.setCode("DHL");
        statusChangedCarrier.setStatus(CarrierStatus.INACTIVE);

        CarrierDTO statusDTO = new CarrierDTO();
        statusDTO.setStatus(CarrierStatus.INACTIVE);

        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        when(carrierRepository.save(any(Carrier.class))).thenReturn(statusChangedCarrier);
        when(carrierMapper.toDto(statusChangedCarrier)).thenReturn(statusDTO);

        CarrierDTO result = carrierService.updateStatus(1L, "INACTIVE");

        assertNotNull(result);
        assertEquals(CarrierStatus.INACTIVE, result.getStatus());
        verify(carrierRepository, times(1)).findById(1L);
        verify(carrierRepository, times(1)).save(any(Carrier.class));
    }

    @Test
    @DisplayName(" updateStatus - Transporteur non trouvé")
    void testUpdateStatusNotFound() {
        when(carrierRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () ->
                carrierService.updateStatus(999L, "ACTIVE")
        );

        verify(carrierRepository, times(1)).findById(999L);
        verify(carrierRepository, never()).save(any());
    }

    // ============================================================
    // TEST: Error Handling
    // ============================================================

    @Test
    @DisplayName(" Error messages - Transporteur non trouvé (findById)")
    void testErrorMessageCarrierNotFoundFindById() {
        when(carrierRepository.findById(1L)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                carrierService.findById(1L)
        );

        assertTrue(exception.getMessage().contains("Carrier avec id specifie pas trouve"));
    }

    @Test
    @DisplayName("Error messages - Transporteur non trouvé (update)")
    void testErrorMessageCarrierNotFoundUpdate() {
        when(carrierRepository.findById(1L)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                carrierService.update(1L, testCarrierDTO)
        );

        assertTrue(exception.getMessage().contains("Carrier non trouvé"));
    }

    @Test
    @DisplayName("Error messages - Transporteur non trouvé (delete)")
    void testErrorMessageCarrierNotFoundDelete() {
        when(carrierRepository.findById(1L)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                carrierService.delete(1L)
        );

        assertTrue(exception.getMessage().contains("Carrier non trouvé"));
    }

    @Test
    @DisplayName("Error messages - Transporteur non trouvé (updateStatus)")
    void testErrorMessageCarrierNotFoundUpdateStatus() {
        when(carrierRepository.findById(1L)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                carrierService.updateStatus(1L, "ACTIVE")
        );

        assertTrue(exception.getMessage().contains("Carrier non trouvé"));
    }

    // ============================================================
    // TEST: Data Integrity
    // ============================================================

    @Test
    @DisplayName("Data validation - Tous les champs dans save")
    void testDataIntegritySave() {
        when(carrierMapper.toEntity(testCarrierDTO)).thenReturn(testCarrier);
        when(carrierRepository.save(testCarrier)).thenReturn(testCarrier);
        when(carrierMapper.toDto(testCarrier)).thenReturn(testCarrierDTO);

        CarrierDTO result = carrierService.save(testCarrierDTO);

        assertNotNull(result.getCode());
        assertNotNull(result.getName());
        assertNotNull(result.getContactEmail());
        assertNotNull(result.getContactPhone());
        assertNotNull(result.getBaseShippingRate());
        assertNotNull(result.getMaxDailyCapacity());
        assertNotNull(result.getCurrentDailyShipments());
        assertNotNull(result.getCutOffTime());
        assertNotNull(result.getStatus());
    }

    @Test
    @DisplayName("Data validation - Tous les champs mis à jour")
    void testDataIntegrityUpdate() {
        CarrierDTO updateDTO = new CarrierDTO();
        updateDTO.setCode("UPS");
        updateDTO.setName("United Parcel Service");
        updateDTO.setContactEmail("info@ups.com");
        updateDTO.setContactPhone("+1111111111");
        updateDTO.setBaseShippingRate(new BigDecimal("45.00"));
        updateDTO.setMaxDailyCapacity(200);
        updateDTO.setCurrentDailyShipments(100);
        updateDTO.setCutOffTime(LocalTime.of(16, 0));
        updateDTO.setStatus(CarrierStatus.ACTIVE);

        Carrier updatedCarrier = new Carrier();
        updatedCarrier.setId(1L);
        updatedCarrier.setCode("UPS");
        updatedCarrier.setName("United Parcel Service");
        updatedCarrier.setContactEmail("info@ups.com");
        updatedCarrier.setContactPhone("+1111111111");
        updatedCarrier.setBaseShippingRate(new BigDecimal("45.00"));
        updatedCarrier.setMaxDailyCapacity(200);
        updatedCarrier.setCurrentDailyShipments(100);
        updatedCarrier.setCutOffTime(LocalTime.of(16, 0));
        updatedCarrier.setStatus(CarrierStatus.ACTIVE);

        when(carrierRepository.findById(1L)).thenReturn(Optional.of(testCarrier));
        when(carrierRepository.save(any(Carrier.class))).thenReturn(updatedCarrier);
        when(carrierMapper.toDto(updatedCarrier)).thenReturn(updateDTO);

        CarrierDTO result = carrierService.update(1L, updateDTO);

        assertEquals("UPS", result.getCode());
        assertEquals("United Parcel Service", result.getName());
        assertEquals("info@ups.com", result.getContactEmail());
    }
}