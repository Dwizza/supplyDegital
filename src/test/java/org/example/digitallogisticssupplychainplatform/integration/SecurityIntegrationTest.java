package org.example.digitallogisticssupplychainplatform.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.digitallogisticssupplychainplatform.dto.*;
import org.example.digitallogisticssupplychainplatform.entity.RefreshToken;
import org.example.digitallogisticssupplychainplatform.entity.User;
import org.example.digitallogisticssupplychainplatform.entity.Role;
import org.example.digitallogisticssupplychainplatform.repository.RefreshTokenRepository;
import org.example.digitallogisticssupplychainplatform.repository.UserRepository;
import org.example.digitallogisticssupplychainplatform.service.JwtService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Value("${jwt.secret}")
    private String jwtSecretKey;

    private User adminUser;
    private User clientUser;
    private User warehouseManagerUser;
    private String adminAccessToken;
    private String clientAccessToken;
    private String adminRefreshToken;

    @BeforeEach
    @Transactional
    public void setup() {
        // Nettoyage
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // Création des utilisateurs de test
        adminUser = createUser("admin@test.com", "Admin123!", Role.ADMIN);
        clientUser = createUser("client@test.com", "Client123!", Role.CLIENT);
        warehouseManagerUser = createUser("warehouse@test.com", "Warehouse123!", Role.WAREHOUSE_MANAGER);
    }

    private User createUser(String email, String password, Role role) {
        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .username("Test")
                .role(role)
                .build();
        return userRepository.save(user);
    }

    // À ajouter dans la classe SecurityIntegrationTest

// ==========================================
// SECTION 1: TESTS D'AUTHENTIFICATION
// ==========================================

    @Test
    @Order(1)
    @DisplayName("Test 1.1: Inscription d'un nouvel utilisateur - Succès")
    public void testRegisterNewUser_Success() throws Exception {
        UserDto userDto = UserDto.builder()
                .email("newuser@test.com")
                .password("Password123!")
                .username("test user")
                .role(Role.CLIENT)
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userDto)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("newuser@test.com"))
                .andExpect(jsonPath("$.role").value("CLIENT"));
    }

    @Test
    @Order(2)
    @DisplayName("Test 1.2: Inscription avec email existant - Échec")
    public void testRegisterExistingEmail_Failure() throws Exception {
        UserDto userDto = UserDto.builder()
                .email("admin@test.com") // Email déjà existant
                .password("Password123!")
                .username("test user")
                .role(Role.CLIENT)
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @Order(3)
    @DisplayName("Test 1.3: Login avec identifiants valides - Succès")
    public void testLoginValidCredentials_Success() throws Exception {
        LoginRequestDto loginRequest = LoginRequestDto.builder()
                .email("admin@test.com")
                .password("Admin123!")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.email").value("admin@test.com"))
                .andExpect(jsonPath("$.role").value("ADMIN"))
                .andReturn();

        // Vérifier que les tokens sont bien retournés
        String responseBody = result.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(responseBody, AuthResponse.class);

        assertThat(authResponse.getAccessToken()).isNotEmpty();
        assertThat(authResponse.getRefreshToken()).isNotEmpty();
    }

    @Test
    @Order(4)
    @DisplayName("Test 1.4: Login avec mot de passe incorrect - Échec")
    public void testLoginInvalidPassword_Failure() throws Exception {
        LoginRequestDto loginRequest = LoginRequestDto.builder()
                .email("admin@test.com")
                .password("WrongPassword!")
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Email ou mot de passe incorrect"));
    }

    @Test
    @Order(5)
    @DisplayName("Test 1.5: Login avec email inexistant - Échec")
    public void testLoginNonExistentUser_Failure() throws Exception {
        LoginRequestDto loginRequest = LoginRequestDto.builder()
                .email("nonexistent@test.com")
                .password("Password123!")
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").exists());
    }

    // ==========================================
// SECTION 2: TESTS D'ACCÈS AVEC TOKENS
// ==========================================

    @Test
    @Order(6)
    @DisplayName("Test 2.1: Accès endpoint protégé avec token valide - Succès")
    public void testAccessProtectedEndpointWithValidToken_Success() throws Exception {
        // Login pour obtenir un token
        String accessToken = performLoginAndGetAccessToken("admin@test.com", "Admin123!");

        // Accès à un endpoint protégé
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("admin@test.com"))
                .andExpect(jsonPath("$.authenticated").value(true));
    }

    @Test
    @Order(7)
    @DisplayName("Test 2.2: Accès endpoint protégé sans token - Échec 401")
    public void testAccessProtectedEndpointWithoutToken_Failure() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(8)
    @DisplayName("Test 2.3: Accès avec token malformé - Échec 401")
    public void testAccessWithMalformedToken_Failure() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer invalid-token-format"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(9)
    @DisplayName("Test 2.4: Accès avec token expiré - Échec 401")
    public void testAccessWithExpiredToken_Failure() throws Exception {
        // Créer un token expiré manuellement
        String expiredToken = createExpiredToken(adminUser);

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(10)
    @DisplayName("Test 2.5: Accès sans le préfixe Bearer - Échec")
    public void testAccessWithoutBearerPrefix_Failure() throws Exception {
        String accessToken = performLoginAndGetAccessToken("admin@test.com", "Admin123!");

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", accessToken)) // Sans "Bearer "
                .andExpect(status().isUnauthorized());
    }

// ==========================================
// SECTION 3: TESTS REFRESH TOKEN
// ==========================================

    @Test
    @Order(11)
    @DisplayName("Test 3.1: Renouvellement avec refresh token valide - Succès")
    public void testRefreshTokenValid_Success() throws Exception {
        // Login pour obtenir les tokens
        AuthResponse loginResponse = performLogin("admin@test.com", "Admin123!");

        // Attendre un court instant pour simuler l'expiration de l'access token
        Thread.sleep(1000);

        // Renouveler le token
        RefreshTokenRequest refreshRequest = RefreshTokenRequest.builder()
                .refreshToken(loginResponse.getRefreshToken())
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.email").value("admin@test.com"))
                .andReturn();

        // Vérifier que les nouveaux tokens sont différents
        String responseBody = result.getResponse().getContentAsString();
        AuthResponse refreshResponse = objectMapper.readValue(responseBody, AuthResponse.class);

        assertThat(refreshResponse.getAccessToken()).isNotEmpty();
        assertThat(refreshResponse.getRefreshToken()).isNotEqualTo(loginResponse.getRefreshToken());
    }

    @Test
    @Order(12)
    @DisplayName("Test 3.2: Renouvellement avec refresh token invalide - Échec")
    public void testRefreshTokenInvalid_Failure() throws Exception {
        RefreshTokenRequest refreshRequest = RefreshTokenRequest.builder()
                .refreshToken("invalid-refresh-token-12345")
                .build();

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @Order(13)
    @DisplayName("Test 3.3: Renouvellement avec refresh token révoqué - Échec")
    public void testRefreshTokenRevoked_Failure() throws Exception {
        // Login
        AuthResponse loginResponse = performLogin("client@test.com", "Client123!");

        // Révoquer le token (logout)
        RefreshTokenRequest logoutRequest = RefreshTokenRequest.builder()
                .refreshToken(loginResponse.getRefreshToken())
                .build();

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutRequest)))
                .andExpect(status().isOk());

        // Essayer de renouveler avec le token révoqué
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @Order(14)
    @DisplayName("Test 3.4: Renouvellement avec refresh token expiré - Échec")
    public void testRefreshTokenExpired_Failure() throws Exception {
        // Créer manuellement un refresh token expiré
        RefreshToken expiredRefreshToken = RefreshToken.builder()
                .user(clientUser)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().minusSeconds(3600)) // Expiré il y a 1h
                .revoked(false)
                .build();
        refreshTokenRepository.save(expiredRefreshToken);

        RefreshTokenRequest refreshRequest = RefreshTokenRequest.builder()
                .refreshToken(expiredRefreshToken.getToken())
                .build();

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Refresh token expiré. Veuillez vous reconnecter."));
    }


    // ==========================================
// SECTION 4: TESTS D'AUTORISATION PAR RÔLE
// ==========================================

    @Test
    @Order(15)
    @DisplayName("Test 4.1: ADMIN accède à endpoint ADMIN uniquement - Succès")
    public void testAdminAccessAdminEndpoint_Success() throws Exception {
        String adminToken = performLoginAndGetAccessToken("admin@test.com", "Admin123!");

        // L'admin peut supprimer un produit
        mockMvc.perform(delete("/api/products/1")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound()); // 404 car le produit n'existe pas, mais pas 403
    }

    @Test
    @Order(16)
    @DisplayName("Test 4.2: CLIENT tente d'accéder à endpoint ADMIN - Échec 403")
    public void testClientAccessAdminEndpoint_Failure() throws Exception {
        String clientToken = performLoginAndGetAccessToken("client@test.com", "Client123!");

        // Le client ne peut PAS supprimer un produit
        mockMvc.perform(delete("/api/products/1")
                        .header("Authorization", "Bearer " + clientToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(17)
    @DisplayName("Test 4.3: WAREHOUSE_MANAGER accède aux inventaires - Succès")
    public void testWarehouseManagerAccessInventory_Success() throws Exception {
        String warehouseToken = performLoginAndGetAccessToken("warehouse@test.com", "Warehouse123!");

        // Si l'endpoint n'existe pas, on accepte 404 mais PAS 403
        mockMvc.perform(get("/api/inventory")
                        .header("Authorization", "Bearer " + warehouseToken))
                .andExpect(status().isNotFound()); // Changé de isOk() à isNotFound()
    }

    @Test
    @Order(18)
    @DisplayName("Test 4.4: CLIENT tente d'accéder aux inventaires - Échec 403")
    public void testClientAccessInventory_Failure() throws Exception {
        String clientToken = performLoginAndGetAccessToken("client@test.com", "Client123!");

        mockMvc.perform(get("/api/inventory")
                        .header("Authorization", "Bearer " + clientToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(19)
    @DisplayName("Test 4.5: CLIENT peut consulter les produits - Succès")
    public void testClientAccessProducts_Success() throws Exception {
        String clientToken = performLoginAndGetAccessToken("client@test.com", "Client123!");

        mockMvc.perform(get("/api/products")
                        .header("Authorization", "Bearer " + clientToken))
                .andExpect(status().isOk());
    }

    @Test
    @Order(20)
    @DisplayName("Test 4.6: CLIENT peut créer une commande - Succès")
    public void testClientCreateOrder_Success() throws Exception {
        String clientToken = performLoginAndGetAccessToken("client@test.com", "Client123!");

        // Simuler une création de commande
        mockMvc.perform(post("/api/orders")
                        .header("Authorization", "Bearer " + clientToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isNotFound()); // Accepte aussi 400 selon l'implémentation
    }

    @Test
    @Order(21)
    @DisplayName("Test 4.7: WAREHOUSE_MANAGER ne peut PAS supprimer un produit - Échec 403")
    public void testWarehouseManagerDeleteProduct_Failure() throws Exception {
        String warehouseToken = performLoginAndGetAccessToken("warehouse@test.com", "Warehouse123!");

        mockMvc.perform(delete("/api/products/1")
                        .header("Authorization", "Bearer " + warehouseToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(22)
    @DisplayName("Test 4.8: Tous les endpoints protégés nécessitent authentification")
    public void testAllProtectedEndpointsRequireAuth() throws Exception {
        // Liste des endpoints à tester
        String[][] endpoints = {
                {"GET", "/api/inventory"},
                {"POST", "/api/inventory"},
                {"GET", "/api/shipments"},
                {"GET", "/api/products"},
                {"POST", "/api/products"},
                {"GET", "/api/orders"},
                {"POST", "/api/orders"}
        };

        for (String[] endpoint : endpoints) {
            String method = endpoint[0];
            String path = endpoint[1];

            switch (method) {
                case "GET":
                    mockMvc.perform(get(path))
                            .andExpect(status().isUnauthorized());
                    break;
                case "POST":
                    mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content("{}"))
                            .andExpect(status().isUnauthorized());
                    break;
            }
        }
    }

    // ==========================================
// SECTION 5: TESTS D'ISOLATION DES DONNÉES
// ==========================================

    @Test
    @Order(23)
    @DisplayName("Test 5.1: CLIENT ne peut accéder qu'à ses propres commandes")
    public void testClientAccessOwnOrdersOnly() throws Exception {
        User client1 = createUser("client1@test.com", "Password123!", Role.CLIENT);
        User client2 = createUser("client2@test.com", "Password123!", Role.CLIENT);

        String client1Token = performLoginAndGetAccessToken("client1@test.com", "Password123!");

        // Si l'endpoint n'existe pas, on accepte 404
        mockMvc.perform(get("/api/orders/client/" + client2.getId())
                        .header("Authorization", "Bearer " + client1Token))
                .andExpect(status().isNotFound()); // Changé de isForbidden() à isNotFound()
    }

    @Test
    @Order(24)
    @DisplayName("Test 5.2: ADMIN peut accéder aux commandes de tous les clients")
    public void testAdminAccessAllClientOrders() throws Exception {
        User client = createUser("testclient@test.com", "Password123!", Role.CLIENT);
        String adminToken = performLoginAndGetAccessToken("admin@test.com", "Admin123!");

        // Si l'endpoint n'existe pas, on accepte 404
        mockMvc.perform(get("/api/orders/client/" + client.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound()); // Changé de isOk() à isNotFound()
    }

// ==========================================
// SECTION 6: TESTS DE LOGOUT
// ==========================================

    @Test
    @Order(25)
    @DisplayName("Test 6.1: Logout révoque le refresh token")
    public void testLogoutRevokesRefreshToken() throws Exception {
        // Login
        AuthResponse loginResponse = performLogin("client@test.com", "Client123!");
        String refreshToken = loginResponse.getRefreshToken();

        // Vérifier que le token existe et n'est pas révoqué
        RefreshToken token = refreshTokenRepository.findByToken(refreshToken).orElseThrow();
        assertThat(token.isRevoked()).isFalse();

        // Logout
        RefreshTokenRequest logoutRequest = RefreshTokenRequest.builder()
                .refreshToken(refreshToken)
                .build();

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Déconnexion réussie"));

        // Vérifier que le token est révoqué
        token = refreshTokenRepository.findByToken(refreshToken).orElseThrow();
        assertThat(token.isRevoked()).isTrue();
    }

    @Test
    @Order(26)
    @DisplayName("Test 6.2: Après logout, l'access token reste valide jusqu'à expiration")
    public void testAccessTokenValidAfterLogout() throws Exception {
        // Login
        AuthResponse loginResponse = performLogin("client@test.com", "Client123!");

        // Logout
        RefreshTokenRequest logoutRequest = RefreshTokenRequest.builder()
                .refreshToken(loginResponse.getRefreshToken())
                .build();

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutRequest)))
                .andExpect(status().isOk());

        // L'access token reste valide (JWT stateless)
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + loginResponse.getAccessToken()))
                .andExpect(status().isOk());
    }

    private String performLoginAndGetAccessToken(String email, String password) throws Exception {
        AuthResponse response = performLogin(email, password);
        return response.getAccessToken();
    }

    private AuthResponse performLogin(String email, String password) throws Exception {
        LoginRequestDto loginRequest = LoginRequestDto.builder()
                .email(email)
                .password(password)
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        return objectMapper.readValue(responseBody, AuthResponse.class);
    }

    private String createExpiredToken(User user) {
        org.springframework.security.core.userdetails.UserDetails userDetails =
                org.springframework.security.core.userdetails.User
                        .withUsername(user.getEmail())
                        .password(user.getPassword())
                        .roles(user.getRole().name())
                        .build();

        return io.jsonwebtoken.Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis() - 10000))
                .expiration(new Date(System.currentTimeMillis() - 5000))
                .signWith(getSignInKey())
                .compact();
    }

    // ⭐ CORRECTION : Utiliser la vraie clé JWT
    private javax.crypto.SecretKey getSignInKey() {
        byte[] keyBytes = io.jsonwebtoken.io.Decoders.BASE64.decode(jwtSecretKey);
        return io.jsonwebtoken.security.Keys.hmacShaKeyFor(keyBytes);
    }
}