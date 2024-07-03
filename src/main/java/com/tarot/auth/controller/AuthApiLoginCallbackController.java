package com.tarot.auth.controller;

import com.tarot.auth.service.LoginService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/login/oauth2", produces = "application/json")
public class AuthApiLoginCallbackController {

    private final LoginService loginService;

    @Operation(summary = "OAuth로그인 콜백", description = "OAuth로그인 콜백", hidden = true)
    @GetMapping("/code/{registrationId}")
    public String  googleLogin(@RequestParam String code, @PathVariable String registrationId) {
        return loginService.socialLogin(code, registrationId);
    }
}