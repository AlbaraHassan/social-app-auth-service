package com.example.authservice.rest.services;


import com.example.authservice.core.config.AppConfig;
import com.example.authservice.core.config.SecurityConfig;
import com.example.authservice.core.exceptions.GeneralException;
import com.example.authservice.core.exceptions.auth.ForbiddenException;
import com.example.authservice.core.exceptions.auth.UnauthorizedException;
import com.example.authservice.core.helpers.JwtService;
import com.example.authservice.core.mailer.MailService;
import com.example.authservice.rest.dtos.AuthDTO;
import com.example.authservice.rest.dtos.UserCreateDTO;
import com.example.authservice.rest.dtos.UserLoginDTO;
import com.example.authservice.rest.feign.UserService;
import com.example.authservice.rest.models.UserModel;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.mail.MessagingException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;

import java.security.Key;
import java.util.Map;
import java.util.Objects;

@Service
public class AuthService {

  private static final String USER_SUBJECT = "user";
  private static final String CODE_SUBJECT = "code";
  private static final Integer TOKEN_EXPIRATION = 24 * 60 * 60 * 1000; // 24 hours

  private final UserService userService;
  private final BCryptPasswordEncoder bcrypt;
  private final AppConfig appConfig;
  private final MailService mailService;
  private final JwtService jwtService;

  public AuthService(UserService userService,
                     SecurityConfig securityConfig,
                     AppConfig appConfig,
                     MailService mailService,
                     JwtService jwtService) {
    this.userService = userService;
    this.bcrypt = securityConfig.bCryptPasswordEncoder();
    this.appConfig = appConfig;
    this.mailService = mailService;
    this.jwtService = jwtService;
  }

  private AuthDTO getToken(UserModel user) {
    return new AuthDTO(
      this.jwtService.sign(Map.of(
        "id", user.getId(),
        "email", user.getEmail(),
        "role", user.getRole(),
        "userName", user.getUserName()
      ), Map.of("exp", TOKEN_EXPIRATION, "subject", USER_SUBJECT))
    );
  }

  private AuthDTO getValidationCode(UserCreateDTO user) {
    return new AuthDTO(
      this.jwtService.sign(Map.of(
        "email", user.getEmail(),
        "role", user.getRole()
      ), Map.of("subject", CODE_SUBJECT))
    );
  }

  public String register(UserCreateDTO data) throws MessagingException {
    String hashedPassword = this.bcrypt.encode(data.getPassword() + this.appConfig.getSalt());
    data.setPassword(hashedPassword);
    String validationCode = this.getValidationCode(data).getAccessToken();
    data.setValidationCode(validationCode);
    UserModel savedUser = this.userService.create(data.toEntity())
      .orElseThrow(() -> new HttpServerErrorException(HttpStatus.BAD_REQUEST, "Error while creating user"));

    sendVerificationEmail(savedUser);

    return savedUser.getEmail();
  }

  public AuthDTO login(UserLoginDTO data) {
    UserModel user = this.getUserByEmail(data.getEmail());

    if (!this.bcrypt.matches(data.getPassword() + this.appConfig.getSalt(), user.getPassword())) {
      throw new UnauthorizedException("Wrong Credentials");
    }
    if (user.getValidationCode() != null) throw new ForbiddenException("Account Not Activated, Please Check Email!");

    return this.getToken(user);
  }

  public AuthDTO verify(String code) {
    Key key = Keys.hmacShaKeyFor(this.appConfig.getSecretKey().getBytes());
    Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(code).getBody();
    UserModel user = this.getUserByEmail((String) claims.get("email"));

    if (!Objects.equals(user.getValidationCode(), code)) {
      throw new ForbiddenException("Wrong validation code");
    }

    user.setValidationCode(null);
    UserModel savedUser = this.userService.verify(user.getId(), user)
      .orElseThrow(() -> new GeneralException("An Error occurred while verifying user"));

    return this.getToken(savedUser);
  }

  private UserModel getUserByEmail(String email) {
    return this.userService.getByEmail(email)
      .orElseThrow(() -> new UnauthorizedException("Wrong Credentials"));
  }

  private void sendVerificationEmail(UserModel user) throws MessagingException {
    String link = this.appConfig.getAppUrl().concat("/signup/verify?code=").concat(user.getValidationCode());
    String emailText = "<p>Please click the following link to complete your registration:</p>\n" +
      "<p><a href=\"" + link + "\">Click here to complete your registration</a></p>";

    this.mailService.sendEmail(user.getEmail(), "No Reply", emailText);
  }
}
