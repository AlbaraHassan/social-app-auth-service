package com.example.authservice.rest.dtos;


import com.example.authservice.rest.enums.Role;
import com.example.authservice.rest.models.UserModel;

public class UserCreateDTO {
  private String email;
  private String userName;
  private String password;
  private Role role = Role.USER;
  private String validationCode;

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

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
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

  public UserModel toEntity(){
    UserModel user = new UserModel();
    user.setValidationCode(this.validationCode);
    user.setEmail(this.email);
    user.setUserName(this.userName);
    user.setPassword(this.password);
    user.setRole(this.role);
    return user;
  }
}
