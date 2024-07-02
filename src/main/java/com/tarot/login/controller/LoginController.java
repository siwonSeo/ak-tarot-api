package com.tarot.login.controller;

import com.tarot.login.service.LoginService;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(value = "/login/oauth2", produces = "application/json")
public class LoginController {

    LoginService loginService;

    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @GetMapping("/code/{registrationId}")
    public String  googleLogin(@RequestParam String code, @PathVariable String registrationId) {
        return loginService.socialLogin(code, registrationId);
    }
}