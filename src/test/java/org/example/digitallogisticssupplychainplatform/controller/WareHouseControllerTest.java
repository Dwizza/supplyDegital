package org.example.digitallogisticssupplychainplatform.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.WareHouseDto;
import org.example.digitallogisticssupplychainplatform.service.WareHouseService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - WareHouseController")
class WareHouseControllerTest {

    private MockMvc mockMvc;

    @Mock
    private WareHouseService wareHouseService;

    @InjectMocks
    private wareHouseController wareHouseControllerInstance;

    private ObjectMapper objectMapper;
    private WareHouseDto testWareHouseDto;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(wareHouseControllerInstance)
                .build();

        objectMapper = new ObjectMapper();

        testWareHouseDto = new WareHouseDto();
        testWareHouseDto.setId(1L);
        testWareHouseDto.setName("Warehouse 1");
        testWareHouseDto.setCode("WH-001");
        testWareHouseDto.setActive(true);
    }


    @Test
    @DisplayName("✓ POST /api/wareHouse - Créer un entrepôt")
    void testCreateWareHouse() throws Exception {
        when(wareHouseService.save(any(WareHouseDto.class))).thenReturn(testWareHouseDto);

        mockMvc.perform(post("/api/wareHouse")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(testWareHouseDto)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1L))
                .andExpect(jsonPath("$.name").value("Warehouse 1"))
                .andExpect(jsonPath("$.code").value("WH-001"));

        verify(wareHouseService, times(1)).save(any(WareHouseDto.class));
    }



    @Test
    @DisplayName("✓ GET /api/wareHouse - Récupérer tous les entrepôts")
    void testGetAllWarehouses() throws Exception {
        List<WareHouseDto> warehouses = new ArrayList<>();
        warehouses.add(testWareHouseDto);

        when(wareHouseService.findAll()).thenReturn(warehouses);

        mockMvc.perform(get("/api/wareHouse")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(1L))
                .andExpect(jsonPath("$[0].name").value("Warehouse 1"));

        verify(wareHouseService, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ GET /api/wareHouse - Liste vide")
    void testGetAllWarehousesEmpty() throws Exception {
        when(wareHouseService.findAll()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/wareHouse")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));

        verify(wareHouseService, times(1)).findAll();
    }



    @Test
    @DisplayName("✓ GET /api/wareHouse/{id} - Récupérer entrepôt par ID")
    void testGetWareHouseById() throws Exception {
        when(wareHouseService.findById(1L)).thenReturn(testWareHouseDto);

        mockMvc.perform(get("/api/wareHouse/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1L))
                .andExpect(jsonPath("$.name").value("Warehouse 1"));

        verify(wareHouseService, times(1)).findById(1L);
    }


    @Test
    @DisplayName("✓ DELETE /api/wareHouse/{id} - Supprimer entrepôt")
    void testDeleteWareHouse() throws Exception {
        doNothing().when(wareHouseService).deleteById(1L);

        mockMvc.perform(delete("/api/wareHouse/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succes").value("wareHouse Deleted Succesufly"));

        verify(wareHouseService, times(1)).deleteById(1L);
    }



    @Test
    @DisplayName("✓ POST retourne CREATED (201)")
    void testPostReturnsCreatedStatus() throws Exception {
        when(wareHouseService.save(any(WareHouseDto.class))).thenReturn(testWareHouseDto);

        mockMvc.perform(post("/api/wareHouse")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(testWareHouseDto)))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("✓ GET retourne OK (200)")
    void testGetReturnsOkStatus() throws Exception {
        when(wareHouseService.findAll()).thenReturn(new ArrayList<>());

        mockMvc.perform(get("/api/wareHouse")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("✓ DELETE retourne OK (200)")
    void testDeleteReturnsOkStatus() throws Exception {
        doNothing().when(wareHouseService).deleteById(1L);

        mockMvc.perform(delete("/api/wareHouse/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }



    @Test
    @DisplayName("✓ Réponses au format JSON")
    void testResponseIsJson() throws Exception {
        when(wareHouseService.save(any(WareHouseDto.class))).thenReturn(testWareHouseDto);

        mockMvc.perform(post("/api/wareHouse")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(testWareHouseDto)))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }



    @Test
    @DisplayName("✓ Opérations multiples - Créer et récupérer")
    void testCreateAndGet() throws Exception {
        when(wareHouseService.save(any(WareHouseDto.class))).thenReturn(testWareHouseDto);

        mockMvc.perform(post("/api/wareHouse")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(testWareHouseDto)))
                .andExpect(status().isCreated());

        when(wareHouseService.findById(1L)).thenReturn(testWareHouseDto);

        mockMvc.perform(get("/api/wareHouse/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1L));
    }
}