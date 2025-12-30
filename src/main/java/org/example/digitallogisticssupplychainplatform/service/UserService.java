package org.example.digitallogisticssupplychainplatform.service;

import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.UserDto;
import org.example.digitallogisticssupplychainplatform.dto.UserResponseDto;
import org.example.digitallogisticssupplychainplatform.entity.User;
import org.example.digitallogisticssupplychainplatform.mapper.UserMapper;
import org.example.digitallogisticssupplychainplatform.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repo;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;


    public UserResponseDto createUser(UserDto userDto) {

        if (repo.existsByEmail(userDto.getEmail())) {
            throw new RuntimeException("Un utilisateur avec ce email existe déjà");
        }

        User user = userMapper.toEntity(userDto);

        String hashedPassword = passwordEncoder.encode(userDto.getPassword());
        user.setPassword(hashedPassword);

        User savedUser = repo.save(user);

        return userMapper.toResponseDto(savedUser);
    }

    public List<UserResponseDto> getAllUsers() {
        return repo.findAll().stream()
                .map(userMapper::toResponseDto)
                .toList();
    }


    public void deleteUser(Long id) {
        repo.deleteById(id);
    }


    public UserResponseDto getById(Long id) {
        return repo.findById(id)
                .map(userMapper::toResponseDto)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec l'ID: " + id));
    }


    public UserResponseDto updateUser(Long id, UserDto userDto) {

        User existingUser = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec l'ID: " + id));

        if (repo.existsByEmailAndIdNot(userDto.getEmail(), id)) {
            throw new RuntimeException("Un utilisateur avec cet email existe déjà");
        }

        existingUser.setUsername(userDto.getUsername());
        existingUser.setEmail(userDto.getEmail());
        existingUser.setRole(userDto.getRole());
        existingUser.setActive(userDto.getActive());

        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {

            if (isAlreadyHashed(userDto.getPassword())) {
                existingUser.setPassword(userDto.getPassword());
            } else {
                String hashedPassword = passwordEncoder.encode(userDto.getPassword());
                existingUser.setPassword(hashedPassword);
            }
        }

        User updatedUser = repo.save(existingUser);

        return userMapper.toResponseDto(updatedUser);
    }


    private boolean isAlreadyHashed(String password) {
        if (password == null) {
            return false;
        }
        return password.startsWith("$2a$") ||
                password.startsWith("$2b$") ||
                password.startsWith("$2y$");
    }


    public UserResponseDto deactivateUser(Long id) {
        User user = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec l'ID: " + id));

        user.setActive(false);
        User deactivatedUser = repo.save(user);

        return userMapper.toResponseDto(deactivatedUser);
    }


    public UserResponseDto activateUser(Long id) {
        User user = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé avec l'ID: " + id));

        user.setActive(true);
        User activatedUser = repo.save(user);

        return userMapper.toResponseDto(activatedUser);
    }
}