package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;
import org.example.digitallogisticssupplychainplatform.entity.Role;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponseDto {
    private Long userId;
    private String username;
    private String email;
    private Role role;
    private boolean active;
    private String message;
    private String token;
}