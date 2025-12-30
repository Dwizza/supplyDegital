package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.SupplierDTO;
import org.example.digitallogisticssupplychainplatform.entity.Supplier;
import org.example.digitallogisticssupplychainplatform.mapper.SupplierMapper;
import org.example.digitallogisticssupplychainplatform.repository.SupplierRepository;
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
@DisplayName("Tests - SupplierService")
class SupplierServiceTest {

    @Mock
    private SupplierRepository supplierRepository;

    @Mock
    private SupplierMapper supplierMapper;

    private SupplierService supplierService;

    private Supplier testSupplier;
    private SupplierDTO testSupplierDTO;

    @BeforeEach
    void setUp() {
        supplierService = SupplierService.builder()
                .repo(supplierRepository)
                .mapper(supplierMapper)
                .build();

        testSupplier = new Supplier();
        testSupplier.setId(1L);
        testSupplier.setName("Supplier 1");
        testSupplier.setContactInfo("contact@supplier.com");

        testSupplierDTO = new SupplierDTO();
        testSupplierDTO.setId(1L);
        testSupplierDTO.setName("Supplier 1");
        testSupplierDTO.setContactInfo("contact@supplier.com");
    }

    // ============================================================
    // TEST: save
    // ============================================================

    @Test
    @DisplayName("✓ save - Créer un nouveau fournisseur")
    void testSaveSuccess() {
        SupplierDTO createDto = new SupplierDTO();
        createDto.setName("Supplier 2");
        createDto.setContactInfo("contact2@supplier.com");

        when(supplierMapper.toEntity(createDto)).thenReturn(testSupplier);
        when(supplierRepository.save(any(Supplier.class))).thenReturn(testSupplier);
        when(supplierMapper.toDto(testSupplier)).thenReturn(testSupplierDTO);

        SupplierDTO result = supplierService.save(createDto);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        assertEquals("Supplier 1", result.getName());
        verify(supplierRepository, times(1)).save(any(Supplier.class));
    }

    // ============================================================
    // TEST: findAll
    // ============================================================

    @Test
    @DisplayName("✓ findAll - Récupérer tous les fournisseurs")
    void testFindAll() {
        List<Supplier> suppliers = new ArrayList<>();
        suppliers.add(testSupplier);

        when(supplierRepository.findAll()).thenReturn(suppliers);
        when(supplierMapper.toDto(testSupplier)).thenReturn(testSupplierDTO);

        List<SupplierDTO> result = supplierService.findAll();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(supplierRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ findAll - Liste vide")
    void testFindAllEmpty() {
        when(supplierRepository.findAll()).thenReturn(new ArrayList<>());

        List<SupplierDTO> result = supplierService.findAll();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(supplierRepository, times(1)).findAll();
    }

    // ============================================================
    // TEST: findById
    // ============================================================

    @Test
    @DisplayName("✓ findById - Récupérer fournisseur par ID")
    void testFindById() {
        when(supplierRepository.findById(1L)).thenReturn(Optional.of(testSupplier));
        when(supplierMapper.toDto(testSupplier)).thenReturn(testSupplierDTO);

        SupplierDTO result = supplierService.findById(1L);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(supplierRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("❌ findById - Fournisseur non trouvé")
    void testFindByIdNotFound() {
        when(supplierRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> supplierService.findById(999L));
        verify(supplierRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: findByName
    // ============================================================

    @Test
    @DisplayName("✓ findByName - Récupérer fournisseur par nom")
    void testFindByName() {
        when(supplierRepository.findByName("Supplier 1")).thenReturn(Optional.of(testSupplier));
        when(supplierMapper.toDto(testSupplier)).thenReturn(testSupplierDTO);

        Optional<SupplierDTO> result = supplierService.findByName("Supplier 1");

        assertTrue(result.isPresent());
        assertEquals("Supplier 1", result.get().getName());
        verify(supplierRepository, times(1)).findByName("Supplier 1");
    }

    @Test
    @DisplayName("✓ findByName - Fournisseur non trouvé")
    void testFindByNameNotFound() {
        when(supplierRepository.findByName("Unknown")).thenReturn(Optional.empty());

        Optional<SupplierDTO> result = supplierService.findByName("Unknown");

        assertFalse(result.isPresent());
        verify(supplierRepository, times(1)).findByName("Unknown");
    }

    // ============================================================
    // TEST: updateSupplier
    // ============================================================

    @Test
    @DisplayName("✓ updateSupplier - Mettre à jour fournisseur")
    void testUpdateSuccess() {
        SupplierDTO updateDto = new SupplierDTO();
        updateDto.setName("Supplier Updated");
        updateDto.setContactInfo("updated@supplier.com");

        Supplier updatedSupplier = new Supplier();
        updatedSupplier.setId(1L);
        updatedSupplier.setName("Supplier Updated");
        updatedSupplier.setContactInfo("updated@supplier.com");

        SupplierDTO resultDto = new SupplierDTO();
        resultDto.setId(1L);
        resultDto.setName("Supplier Updated");
        resultDto.setContactInfo("updated@supplier.com");

        when(supplierRepository.findById(1L)).thenReturn(Optional.of(testSupplier));
        when(supplierRepository.save(any(Supplier.class))).thenReturn(updatedSupplier);
        when(supplierMapper.toDto(updatedSupplier)).thenReturn(resultDto);

        SupplierDTO result = supplierService.updateSupplier(1L, updateDto);

        assertNotNull(result);
        assertEquals("Supplier Updated", result.getName());
        verify(supplierRepository, times(1)).findById(1L);
        verify(supplierRepository, times(1)).save(any(Supplier.class));
    }

    @Test
    @DisplayName("❌ updateSupplier - Fournisseur non trouvé")
    void testUpdateNotFound() {
        SupplierDTO updateDto = new SupplierDTO();
        updateDto.setName("Test");

        when(supplierRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> supplierService.updateSupplier(999L, updateDto));
        verify(supplierRepository, times(1)).findById(999L);
    }

    // ============================================================
    // TEST: deleteById
    // ============================================================

    @Test
    @DisplayName("✓ deleteById - Supprimer fournisseur")
    void testDeleteSuccess() {
        doNothing().when(supplierRepository).deleteById(1L);

        supplierService.deleteById(1L);

        verify(supplierRepository, times(1)).deleteById(1L);
    }

    // ============================================================
    // TEST: Multiple operations
    // ============================================================

    @Test
    @DisplayName("✓ Opérations multiples - Créer et récupérer")
    void testCreateAndGet() {
        SupplierDTO createDto = new SupplierDTO();
        createDto.setName("Supplier 2");

        when(supplierMapper.toEntity(createDto)).thenReturn(testSupplier);
        when(supplierRepository.save(any())).thenReturn(testSupplier);
        when(supplierMapper.toDto(testSupplier)).thenReturn(testSupplierDTO);

        SupplierDTO created = supplierService.save(createDto);
        assertNotNull(created);

        when(supplierRepository.findById(1L)).thenReturn(Optional.of(testSupplier));
        SupplierDTO retrieved = supplierService.findById(1L);
        assertNotNull(retrieved);
        assertEquals(created.getId(), retrieved.getId());
    }

    @Test
    @DisplayName("✓ Opérations multiples - Créer et mettre à jour")
    void testCreateAndUpdate() {
        SupplierDTO createDto = new SupplierDTO();
        createDto.setName("Supplier 2");

        when(supplierMapper.toEntity(createDto)).thenReturn(testSupplier);
        when(supplierRepository.save(any())).thenReturn(testSupplier);
        when(supplierMapper.toDto(testSupplier)).thenReturn(testSupplierDTO);

        SupplierDTO created = supplierService.save(createDto);
        assertNotNull(created);

        SupplierDTO updateDto = new SupplierDTO();
        updateDto.setName("Updated");

        when(supplierRepository.findById(1L)).thenReturn(Optional.of(testSupplier));
        when(supplierRepository.save(any())).thenReturn(testSupplier);
        SupplierDTO updated = supplierService.updateSupplier(1L, updateDto);
        assertNotNull(updated);
    }
}