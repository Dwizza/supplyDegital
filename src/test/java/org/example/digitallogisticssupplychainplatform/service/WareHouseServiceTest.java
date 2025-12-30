package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.WareHouseDto;
import org.example.digitallogisticssupplychainplatform.entity.WareHouse;
import org.example.digitallogisticssupplychainplatform.mapper.WareHouseMapper;
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
@DisplayName("Tests - WareHouseService")
class WareHouseServiceTest {

    @Mock
    private WareHouseRepository wareHouseRepository;

    @Mock
    private WareHouseMapper wareHouseMapper;

    private WareHouseService wareHouseService;

    private WareHouse testWareHouse;
    private WareHouseDto testWareHouseDto;

    @BeforeEach
    void setUp() {
        wareHouseService = new WareHouseService(wareHouseRepository, wareHouseMapper);

        testWareHouse = new WareHouse();
        testWareHouse.setId(1L);
        testWareHouse.setName("Warehouse 1");
        testWareHouse.setCode("WH-001");
        testWareHouse.setActive(true);

        testWareHouseDto = new WareHouseDto();
        testWareHouseDto.setId(1L);
        testWareHouseDto.setName("Warehouse 1");
        testWareHouseDto.setCode("WH-001");
        testWareHouseDto.setActive(true);
    }

    // ============================================================
    // TEST: save
    // ============================================================

    @Test
    @DisplayName("✓ save - Créer un nouvel entrepôt")
    void testSaveSuccess() {
        WareHouseDto createDto = new WareHouseDto();
        createDto.setName("Warehouse 2");
        createDto.setCode("WH-002");
        createDto.setActive(true);

        when(wareHouseMapper.toEntity(createDto)).thenReturn(testWareHouse);
        when(wareHouseRepository.save(any(WareHouse.class))).thenReturn(testWareHouse);
        when(wareHouseMapper.toResponseDto(testWareHouse)).thenReturn(testWareHouseDto);

        WareHouseDto result = wareHouseService.save(createDto);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        assertEquals("Warehouse 1", result.getName());
        verify(wareHouseRepository, times(1)).save(any(WareHouse.class));
    }

    // ============================================================
    // TEST: findAll
    // ============================================================

    @Test
    @DisplayName("✓ findAll - Récupérer tous les entrepôts")
    void testFindAll() {
        List<WareHouse> wareHouses = new ArrayList<>();
        wareHouses.add(testWareHouse);

        when(wareHouseRepository.findAll()).thenReturn(wareHouses);
        when(wareHouseMapper.toResponseDto(testWareHouse)).thenReturn(testWareHouseDto);

        List<WareHouseDto> result = wareHouseService.findAll();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(wareHouseRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ findAll - Liste vide")
    void testFindAllEmpty() {
        when(wareHouseRepository.findAll()).thenReturn(new ArrayList<>());

        List<WareHouseDto> result = wareHouseService.findAll();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(wareHouseRepository, times(1)).findAll();
    }

    // ============================================================
    // TEST: findById
    // ============================================================

    @Test
    @DisplayName("✓ findById - Récupérer entrepôt par ID")
    void testFindById() {
        when(wareHouseRepository.findById(1L)).thenReturn(Optional.of(testWareHouse));
        when(wareHouseMapper.toResponseDto(testWareHouse)).thenReturn(testWareHouseDto);

        WareHouseDto result = wareHouseService.findById(1L);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(wareHouseRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("❌ findById - Entrepôt non trouvé")
    void testFindByIdNotFound() {
        when(wareHouseRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> wareHouseService.findById(999L));
        verify(wareHouseRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: updateWareHouse
    // ============================================================

    @Test
    @DisplayName("✓ updateWareHouse - Mettre à jour entrepôt")
    void testUpdateSuccess() {
        WareHouseDto updateDto = new WareHouseDto();
        updateDto.setName("Warehouse Updated");
        updateDto.setCode("WH-001");
        updateDto.setActive(true);

        WareHouse updatedWareHouse = new WareHouse();
        updatedWareHouse.setId(1L);
        updatedWareHouse.setName("Warehouse Updated");
        updatedWareHouse.setCode("WH-001");

        WareHouseDto resultDto = new WareHouseDto();
        resultDto.setId(1L);
        resultDto.setName("Warehouse Updated");
        resultDto.setCode("WH-001");

        when(wareHouseRepository.findById(1L)).thenReturn(Optional.of(testWareHouse));
        when(wareHouseRepository.save(any(WareHouse.class))).thenReturn(updatedWareHouse);
        when(wareHouseMapper.toResponseDto(updatedWareHouse)).thenReturn(resultDto);

        WareHouseDto result = wareHouseService.updateWareHouse(1L, updateDto);

        assertNotNull(result);
        assertEquals("Warehouse Updated", result.getName());
        verify(wareHouseRepository, times(1)).findById(1L);
        verify(wareHouseRepository, times(1)).save(any(WareHouse.class));
    }

    @Test
    @DisplayName("❌ updateWareHouse - Entrepôt non trouvé")
    void testUpdateNotFound() {
        WareHouseDto updateDto = new WareHouseDto();
        updateDto.setName("Test");

        when(wareHouseRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> wareHouseService.updateWareHouse(999L, updateDto));
        verify(wareHouseRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: deleteById
    // ============================================================

    @Test
    @DisplayName("✓ deleteById - Supprimer entrepôt")
    void testDeleteSuccess() {
        doNothing().when(wareHouseRepository).deleteById(1L);

        wareHouseService.deleteById(1L);

        verify(wareHouseRepository, times(1)).deleteById(1L);
    }

    // ============================================================
    // TEST: Multiple operations
    // ============================================================

    @Test
    @DisplayName("✓ Opérations multiples - Créer et récupérer")
    void testCreateAndGet() {
        WareHouseDto createDto = new WareHouseDto();
        createDto.setName("Warehouse 2");

        when(wareHouseMapper.toEntity(createDto)).thenReturn(testWareHouse);
        when(wareHouseRepository.save(any())).thenReturn(testWareHouse);
        when(wareHouseMapper.toResponseDto(testWareHouse)).thenReturn(testWareHouseDto);

        WareHouseDto created = wareHouseService.save(createDto);
        assertNotNull(created);

        when(wareHouseRepository.findById(1L)).thenReturn(Optional.of(testWareHouse));
        WareHouseDto retrieved = wareHouseService.findById(1L);
        assertNotNull(retrieved);
        assertEquals(created.getId(), retrieved.getId());
    }

    @Test
    @DisplayName("✓ Opérations multiples - Créer et mettre à jour")
    void testCreateAndUpdate() {
        WareHouseDto createDto = new WareHouseDto();
        createDto.setName("Warehouse 2");

        when(wareHouseMapper.toEntity(createDto)).thenReturn(testWareHouse);
        when(wareHouseRepository.save(any())).thenReturn(testWareHouse);
        when(wareHouseMapper.toResponseDto(testWareHouse)).thenReturn(testWareHouseDto);

        WareHouseDto created = wareHouseService.save(createDto);
        assertNotNull(created);

        WareHouseDto updateDto = new WareHouseDto();
        updateDto.setName("Updated");

        when(wareHouseRepository.findById(1L)).thenReturn(Optional.of(testWareHouse));
        when(wareHouseRepository.save(any())).thenReturn(testWareHouse);
        WareHouseDto updated = wareHouseService.updateWareHouse(1L, updateDto);
        assertNotNull(updated);
    }
}