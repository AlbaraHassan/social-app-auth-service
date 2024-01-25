package com.example.authservice.core.exceptions.handlers;

import com.example.authservice.core.exceptions.ErrorResponse;
import com.example.authservice.core.exceptions.GeneralException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(GeneralException.class)
  public ResponseEntity<ErrorResponse> handleHttpServerErrorException(GeneralException ex) {
    String responseBody = ex.getMessage();
    String message = responseBody.isEmpty() ? "No message provided" : responseBody;
    ErrorResponse errorResponse = new ErrorResponse(ex.getStatusCode(), message);
    return ResponseEntity.status(ex.getStatusCode()).body(errorResponse);
  }
}
