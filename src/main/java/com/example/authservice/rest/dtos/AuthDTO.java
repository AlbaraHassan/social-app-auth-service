package com.example.authservice.rest.dtos;

public class AuthDTO {

  private String accessToken;

  public AuthDTO(String accessToken) {
    this.accessToken = accessToken;
  }

  public String getAccessToken() {
    return accessToken;
  }
}
