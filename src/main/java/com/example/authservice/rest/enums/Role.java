package com.example.authservice.rest.enums;

public enum Role {
  ADMIN("admin"),
  USER("user");

  private final String roleName;

  Role(String roleName) {
    this.roleName = roleName;
  }

  public String getRoleName() {
    return roleName;
  }
}
