package com.example.authservice.core.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

  @Value("${configuration.jwt.secret}")
  private String secretKey;

  @Value("${configuration.security.salt}")
  private String salt;

  @Value("${APP_URL}")
  private String appUrl;

  public String getSecretKey() {
    return this.secretKey;
  }

  public String getSalt() {
    return this.salt;
  }

  public String getAppUrl() {
    return this.appUrl;
  }
}
