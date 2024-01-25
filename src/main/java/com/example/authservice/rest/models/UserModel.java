package com.example.authservice.rest.models;

import com.example.authservice.rest.enums.Role;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;


@Document("user")
public class UserModel {


  @Id
  private String id;

  private String email;
  private String userName;
  private String password;
  private Role role = Role.USER;

  public void setRole(Role role) {
    this.role = role;
  }

  private String validationCode;

  public String getId() {
    return this.id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getEmail() {
    return this.email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getUserName() {
    return this.userName;
  }

  public void setUserName(String userName) {
    this.userName = userName;
  }

  public String getPassword() {
    return this.password;
  }

  public Role getRole() {
    return this.role;
  }

  public void setPassword(String password) {
    this.password = password;
  }


  public UserModel() {
  }

  public UserModel(String email, String userName, String password, Role role, String validationCode) {
    this.email = email;
    this.userName = userName;
    this.password = password;
    this.role = role != null ? role : Role.USER;
    this.validationCode = validationCode;

  }


  public String getValidationCode() {
    return validationCode;
  }

  public void setValidationCode(String validationCode) {
    this.validationCode = validationCode;
  }
}