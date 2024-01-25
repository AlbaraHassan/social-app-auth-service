package com.example.authservice.core.exceptions.general;

import com.example.authservice.core.exceptions.GeneralException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.NOT_FOUND)
public class NotFoundException extends GeneralException {
  public NotFoundException() {
    super(HttpStatus.NOT_FOUND.value());
  }

  public NotFoundException(String message) {
    super(HttpStatus.NOT_FOUND.value(), message);
  }
}