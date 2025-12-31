package org.example.digitallogisticssupplychainplatform.service;

import org.example.digitallogisticssupplychainplatform.dto.UserDto;
import org.example.digitallogisticssupplychainplatform.dto.UserResponseDto;
import org.example.digitallogisticssupplychainplatform.entity.Role;
import org.example.digitallogisticssupplychainplatform.entity.User;
import org.example.digitallogisticssupplychainplatform.mapper.UserMapper;
import org.example.digitallogisticssupplychainplatform.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("Tests - UserService")
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserMapper userMapper;

    @Mock
    private PasswordEncoder passwordEncoder;  // ✅ AJOUTER CETTE MOCK

    private UserService userService;

    private User testUser;
    private UserDto testUserDto;
    private UserResponseDto testUserResponseDto;

    @BeforeEach
    void setUp() {
        // ✅ INITIALISER AVEC 3 PARAMÈTRES
        userService = new UserService(userRepository, userMapper);

        // ✅ CONFIGURER LE MOCK PASSWORDENCODER (lenient car pas utilisé dans tous les tests)
        lenient().when(passwordEncoder.encode("password123"))
                .thenReturn("$2a$12$R9h7cIPz0gi.URNNW3.KMeM7z0H.K4e7qYz...");
        lenient().when(passwordEncoder.encode("newpassword"))
                .thenReturn("$2a$12$K2m4cXpQ1gi.URXYW5.NOdM8z2H.M5f8rZa...");

        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setEmail("test@test.com");
        testUser.setPassword("$2a$12$R9h7cIPz0gi.URNNW3.KMeM7z0H.K4e7qYz...");  // Hash BCrypt
        testUser.setRole(Role.CLIENT);
        testUser.setActive(true);

        testUserDto = new UserDto();
        testUserDto.setUsername("testuser");
        testUserDto.setEmail("test@test.com");
        testUserDto.setPassword("password123");
        testUserDto.setRole(Role.CLIENT);
        testUserDto.setActive(true);

        testUserResponseDto = new UserResponseDto();
        testUserResponseDto.setId(1L);
        testUserResponseDto.setUsername("testuser");
        testUserResponseDto.setEmail("test@test.com");
        testUserResponseDto.setRole(Role.CLIENT);
        testUserResponseDto.setActive(true);
    }

    // ============================================================
    // TEST: createUser
    // ============================================================

    @Test
    @DisplayName("✓ createUser - Créer un nouvel utilisateur")
    void testCreateUserSuccess() {
        when(userRepository.existsByEmail("test@test.com")).thenReturn(false);
        when(userMapper.toEntity(testUserDto)).thenReturn(testUser);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(userMapper.toResponseDto(testUser)).thenReturn(testUserResponseDto);

        UserResponseDto result = userService.createUser(testUserDto);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        assertEquals("testuser", result.getUsername());

        // ✅ VÉRIFIER QUE LE PASSWORD A ÉTÉ ENCODÉ
        verify(passwordEncoder, times(1)).encode("password123");
        verify(userRepository, times(1)).existsByEmail("test@test.com");
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("❌ createUser - Email déjà existant")
    void testCreateUserEmailExists() {
        when(userRepository.existsByEmail("test@test.com")).thenReturn(true);

        assertThrows(RuntimeException.class, () -> userService.createUser(testUserDto));
        verify(userRepository, times(1)).existsByEmail("test@test.com");
        verify(userRepository, never()).save(any());
    }


    @Test
    @DisplayName("✓ getAllUsers - Récupérer tous les utilisateurs")
    void testGetAllUsers() {
        List<User> users = new ArrayList<>();
        users.add(testUser);

        when(userRepository.findAll()).thenReturn(users);
        when(userMapper.toResponseDto(testUser)).thenReturn(testUserResponseDto);

        List<UserResponseDto> result = userService.getAllUsers();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(userRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("✓ getAllUsers - Liste vide")
    void testGetAllUsersEmpty() {
        when(userRepository.findAll()).thenReturn(new ArrayList<>());

        List<UserResponseDto> result = userService.getAllUsers();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(userRepository, times(1)).findAll();
    }



    @Test
    @DisplayName("✓ getById - Récupérer utilisateur par ID")
    void testGetById_Success() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(userMapper.toResponseDto(testUser)).thenReturn(testUserResponseDto);

        UserResponseDto result = userService.getById(1L);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(userRepository, times(1)).findById(1L);
    }

    @Test
    @DisplayName("❌ getById - Utilisateur non trouvé")
    void testGetById_NotFound() {
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> userService.getById(999L));
        verify(userRepository, times(1)).findById(999L);
    }



    @Test
    @DisplayName("✓ updateUser - Mettre à jour utilisateur avec nouveau password")
    void testUpdateUser_WithNewPassword() {
        UserDto updateDto = new UserDto();
        updateDto.setUsername("updateduser");
        updateDto.setEmail("updated@test.com");
        updateDto.setPassword("newpassword");
        updateDto.setRole(Role.ADMIN);
        updateDto.setActive(true);

        User existingUser = new User();
        existingUser.setId(1L);
        existingUser.setUsername("testuser");
        existingUser.setEmail("test@test.com");
        existingUser.setPassword("$2a$12$oldHash...");

        User updatedUser = new User();
        updatedUser.setId(1L);
        updatedUser.setUsername("updateduser");
        updatedUser.setEmail("updated@test.com");

        UserResponseDto resultDto = new UserResponseDto();
        resultDto.setId(1L);
        resultDto.setUsername("updateduser");
        resultDto.setEmail("updated@test.com");

        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(userRepository.existsByEmailAndIdNot("updated@test.com", 1L)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(updatedUser);
        when(userMapper.toResponseDto(updatedUser)).thenReturn(resultDto);

        UserResponseDto result = userService.updateUser(1L, updateDto);

        assertNotNull(result);
        assertEquals("updateduser", result.getUsername());

        verify(passwordEncoder, times(1)).encode("newpassword");
        verify(userRepository, times(1)).findById(1L);
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("✓ updateUser - Mettre à jour SANS changer le password")
    void testUpdateUser_WithoutPassword() {
        UserDto updateDto = new UserDto();
        updateDto.setUsername("updateduser");
        updateDto.setEmail("updated@test.com");
        updateDto.setPassword(null);  // ← Pas de password
        updateDto.setRole(Role.ADMIN);
        updateDto.setActive(true);

        User existingUser = new User();
        existingUser.setId(1L);
        existingUser.setUsername("testuser");
        existingUser.setEmail("test@test.com");
        existingUser.setPassword("$2a$12$oldHash...");

        User updatedUser = new User();
        updatedUser.setId(1L);
        updatedUser.setUsername("updateduser");
        updatedUser.setEmail("updated@test.com");

        UserResponseDto resultDto = new UserResponseDto();
        resultDto.setId(1L);
        resultDto.setUsername("updateduser");
        resultDto.setEmail("updated@test.com");

        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(userRepository.existsByEmailAndIdNot("updated@test.com", 1L)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(updatedUser);
        when(userMapper.toResponseDto(updatedUser)).thenReturn(resultDto);

        UserResponseDto result = userService.updateUser(1L, updateDto);

        assertNotNull(result);
        assertEquals("updateduser", result.getUsername());

        // ✅ VÉRIFIER QUE LE PASSWORD N'A PAS ÉTÉ ENCODÉ
        verify(passwordEncoder, never()).encode(any());
        verify(userRepository, times(1)).findById(1L);
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("❌ updateUser - Utilisateur non trouvé")
    void testUpdateUser_NotFound() {
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> userService.updateUser(999L, testUserDto));
        verify(userRepository, times(1)).findById(999L);
    }

    @Test
    @DisplayName("❌ updateUser - Email déjà utilisé par un autre utilisateur")
    void testUpdateUser_EmailExists() {
        UserDto updateDto = new UserDto();
        updateDto.setEmail("existing@test.com");

        User existingUser = new User();
        existingUser.setId(1L);
        existingUser.setEmail("test@test.com");

        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(userRepository.existsByEmailAndIdNot("existing@test.com", 1L)).thenReturn(true);

        assertThrows(RuntimeException.class, () -> userService.updateUser(1L, updateDto));
        verify(userRepository, times(1)).findById(1L);
        verify(userRepository, never()).save(any());
    }


    @Test
    @DisplayName("✓ deleteUser - Supprimer utilisateur")
    void testDeleteUser() {
        doNothing().when(userRepository).deleteById(1L);

        userService.deleteUser(1L);

        verify(userRepository, times(1)).deleteById(1L);
    }



    @Test
    @DisplayName("✓ deactivateUser - Désactiver un utilisateur")
    void testDeactivateUser() {
        User userToDeactivate = new User();
        userToDeactivate.setId(1L);
        userToDeactivate.setActive(true);

        UserResponseDto deactivatedDto = new UserResponseDto();
        deactivatedDto.setId(1L);
        deactivatedDto.setActive(false);

        when(userRepository.findById(1L)).thenReturn(Optional.of(userToDeactivate));
        when(userRepository.save(any(User.class))).thenReturn(userToDeactivate);
        when(userMapper.toResponseDto(any(User.class))).thenReturn(deactivatedDto);

        UserResponseDto result = userService.deactivateUser(1L);

        assertNotNull(result);
        verify(userRepository, times(1)).save(any(User.class));
    }



    @Test
    @DisplayName("✓ activateUser - Réactiver un utilisateur")
    void testActivateUser() {
        User userToActivate = new User();
        userToActivate.setId(1L);
        userToActivate.setActive(false);

        UserResponseDto activatedDto = new UserResponseDto();
        activatedDto.setId(1L);
        activatedDto.setActive(true);

        when(userRepository.findById(1L)).thenReturn(Optional.of(userToActivate));
        when(userRepository.save(any(User.class))).thenReturn(userToActivate);
        when(userMapper.toResponseDto(any(User.class))).thenReturn(activatedDto);

        UserResponseDto result = userService.activateUser(1L);

        assertNotNull(result);
        verify(userRepository, times(1)).save(any(User.class));
    }



    @Test
    @DisplayName("✓ Opérations multiples - Créer et récupérer")
    void testCreateAndGet() {
        when(userRepository.existsByEmail("test@test.com")).thenReturn(false);
        when(userMapper.toEntity(testUserDto)).thenReturn(testUser);
        when(userRepository.save(any())).thenReturn(testUser);
        when(userMapper.toResponseDto(testUser)).thenReturn(testUserResponseDto);

        UserResponseDto created = userService.createUser(testUserDto);
        assertNotNull(created);

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        UserResponseDto retrieved = userService.getById(1L);
        assertNotNull(retrieved);
        assertEquals(created.getId(), retrieved.getId());
    }

    @Test
    @DisplayName("✓ Opérations multiples - Créer et mettre à jour")
    void testCreateAndUpdate() {
        when(userRepository.existsByEmail("test@test.com")).thenReturn(false);
        when(userMapper.toEntity(testUserDto)).thenReturn(testUser);
        when(userRepository.save(any())).thenReturn(testUser);
        when(userMapper.toResponseDto(testUser)).thenReturn(testUserResponseDto);

        UserResponseDto created = userService.createUser(testUserDto);
        assertNotNull(created);

        UserDto updateDto = new UserDto();
        updateDto.setUsername("updated");
        updateDto.setEmail("updated@test.com");
        updateDto.setPassword("password123");
        updateDto.setRole(Role.CLIENT);
        updateDto.setActive(true);

        User existingUser = new User();
        existingUser.setId(1L);

        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(userRepository.existsByEmailAndIdNot("updated@test.com", 1L)).thenReturn(false);
        when(userRepository.save(any())).thenReturn(testUser);
        when(userMapper.toResponseDto(any())).thenReturn(testUserResponseDto);

        UserResponseDto updated = userService.updateUser(1L, updateDto);
        assertNotNull(updated);
    }
}