package org.example.digitallogisticssupplychainplatform.dto;
import lombok.*;
import org.example.digitallogisticssupplychainplatform.entity.Role;
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponseDto {
    private Long id;
    private String username;
    private String email;
    private Role role;
    private boolean active;
}
