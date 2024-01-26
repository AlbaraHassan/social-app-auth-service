package com.example.authservice.rest.feign;

import com.example.authservice.rest.dtos.UserDTO;
import com.example.authservice.rest.models.UserModel;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@FeignClient(name = "USER-SERVICE", path = "/api/user", url = "https://user-service-ejol.onrender.com")
public interface UserService {

  @GetMapping("/all")
  Optional<List<UserDTO>> getAll();

  @GetMapping
  Optional<UserDTO> get(@RequestParam String id);

  @GetMapping("/getMe")
  UserDTO getMe(@RequestHeader("Authorization") String authorizationHeader);

  @DeleteMapping
  boolean delete(@RequestParam String id);

  @PostMapping
  Optional<UserModel> create(@RequestBody UserModel data);

  @PostMapping("/verify")
  Optional<UserModel> verify(@RequestParam String id, @RequestBody UserModel data);

  @GetMapping("/email")
  Optional<UserModel> getByEmail(@RequestParam String email);
}
