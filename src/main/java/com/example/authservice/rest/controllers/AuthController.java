package com.example.authservice.rest.controllers;


import com.example.authservice.rest.dtos.AuthDTO;
import com.example.authservice.rest.dtos.UserCreateDTO;
import com.example.authservice.rest.dtos.UserLoginDTO;
import com.example.authservice.rest.services.AuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/auth")
@Tag(name = "Auth")
public class AuthController {

  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("/register")
  public String register(@RequestBody UserCreateDTO data) throws MessagingException {
    return this.authService.register(data);
  }

  @GetMapping("/verify")
  public AuthDTO verify(@RequestParam String code) {
    return this.authService.verify(code);
  }

  @PostMapping("/login")
  public AuthDTO login(@RequestBody UserLoginDTO data) {
    return this.authService.login(data);
  }
}
