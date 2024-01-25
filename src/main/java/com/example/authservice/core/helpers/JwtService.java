package com.example.authservice.core.helpers;


import com.example.authservice.core.config.AppConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

  private final AppConfig appConfig;
  private final Key key;

  public JwtService(AppConfig appConfig) {
    this.appConfig = appConfig;
    this.key = Keys.hmacShaKeyFor(this.appConfig.getSecretKey().getBytes());
  }


  public String sign(Map<String, Object> claims, Map<String, Object> options) {
    return Jwts.builder()
      .setSubject((String) options.get("subject"))
      .setClaims(claims)
      .setIssuedAt(new Date(System.currentTimeMillis()))
      .setExpiration(options.containsKey("exp") ? new Date(System.currentTimeMillis() + (Integer) options.get("exp")) : null)
      .signWith(this.key)
      .compact();
  }

  public Claims decode(String token) {
    try {
      return Jwts.parserBuilder().setSigningKey(this.key).build().parseClaimsJws(token).getBody();
    } catch (ExpiredJwtException e) {
      return e.getClaims();
    }
  }
}
