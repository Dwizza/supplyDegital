package org.example.digitallogisticssupplychainplatform.mapper;

import org.example.digitallogisticssupplychainplatform.dto.UserDto;
import org.example.digitallogisticssupplychainplatform.dto.UserResponseDto;
import org.example.digitallogisticssupplychainplatform.entity.Role;
import org.example.digitallogisticssupplychainplatform.entity.User;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    public User toEntity(UserDto userDto){
        if(userDto==null){
            return null;
        }

        return User.builder().
                username(userDto.getUsername()).email(userDto.getEmail()).
                password(userDto.getPassword()).role(userDto.getRole()).build();
    }

    public UserResponseDto toResponseDto(User user){
        if(user==null){
            return null;
        }

        return UserResponseDto.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .id(user.getId())
                .role(user.getRole()).active(user.isActive()).build();
    }
}
