package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;
import org.example.digitallogisticssupplychainplatform.entity.Role;
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
    private String username;
    private String email;
    private String password;
    private Role role;
    private Boolean active;

}
