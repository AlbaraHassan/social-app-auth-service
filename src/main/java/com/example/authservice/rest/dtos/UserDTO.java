package com.example.authservice.rest.dtos;

import com.example.authservice.rest.enums.Role;
import com.example.authservice.rest.models.UserModel;
import io.jsonwebtoken.Claims;
import jakarta.validation.constraints.NotBlank;

public class UserDTO {
  @NotBlank
  private String id;

  @NotBlank
  private String email;
  @NotBlank
  private String userName;
  @NotBlank
  private Role role = Role.USER;

  public UserDTO(UserModel user) {
    this.id = user.getId();
    this.email = user.getEmail();
    this.userName = user.getUserName();
    this.role = user.getRole();
  }

  public UserDTO(Claims claims) {
    this.id = (String) claims.get("id");
    this.userName = (String) claims.get("userName");
    this.email = (String) claims.get("email");
    this.role = Role.valueOf(((String) claims.get("role")).toUpperCase());
  }

  public UserDTO(){}

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getUserName() {
    return userName;
  }

  public void setUserName(String userName) {
    this.userName = userName;
  }

  public Role getRole() {
    return role;
  }

  public void setRole(Role role) {
    this.role = role;
  }

  public String getValidationCode() {
    return validationCode;
  }

  public void setValidationCode(String validationCode) {
    this.validationCode = validationCode;
  }

  private String validationCode;
}
