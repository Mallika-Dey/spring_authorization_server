package com.example.authserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * LoginController
 *
 * @author Mallika Dey
 */
@Controller
public class LoginController {
  @GetMapping("/login")
  public String login() {
    return "login";
  }
}
