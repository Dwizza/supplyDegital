package org.example.digitallogisticssupplychainplatform.controller;

import jakarta.validation.Valid;
import org.example.digitallogisticssupplychainplatform.dto.UserDto;
import org.example.digitallogisticssupplychainplatform.dto.UserResponseDto;
import org.example.digitallogisticssupplychainplatform.entity.User;
import org.example.digitallogisticssupplychainplatform.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.function.EntityResponse;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequestMapping("api/users")
@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService){
        this.userService=userService;
    }
@PostMapping
    public ResponseEntity<UserResponseDto> createUser(@Valid @RequestBody UserDto userDto){
        try {
            UserResponseDto userCreated = userService.createUser(userDto);
            return ResponseEntity.status(HttpStatus.CREATED).body(userCreated);
        }
        catch (Exception e){
            System.out.println("-------------------");
            System.out.println(e.getMessage());
            System.out.println("-------------------");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }

    @GetMapping
    public ResponseEntity <List<UserResponseDto>>findAll(){
        List<UserResponseDto> users=userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

  @DeleteMapping("/{id}")
    public ResponseEntity<Map<String,String>>removeUser(@PathVariable Long id){
        userService.deleteUser(id);
     Map<String,String>response=new HashMap<>();
     response.put("succes","user deleted succesefly");
     return ResponseEntity.ok(response);
  }

  @GetMapping("/{id}")
    public ResponseEntity<UserResponseDto>getUser(@PathVariable Long id){
        UserResponseDto user=userService.getById(id);
        return ResponseEntity.ok(user);
  }

  @PutMapping("/{id}")
    public ResponseEntity<?>update(@PathVariable long id,@Valid @RequestBody UserDto user){
        try {
            UserResponseDto userUpdated=userService.updateUser(id,user);
            return ResponseEntity.ok(userUpdated);
        }catch (Exception e){
            Map<String,String>response=new HashMap<>();
            response.put("error",e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

        }

  }
}
