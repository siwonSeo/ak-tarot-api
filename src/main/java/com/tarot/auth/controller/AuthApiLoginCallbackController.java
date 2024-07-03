package com.tarot.auth.controller;

import com.tarot.auth.dto.response.ResponseToken;
import com.tarot.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/login/oauth2", produces = "application/json")
public class AuthApiLoginCallbackController {

    private final AuthService authService;

    @Operation(summary = "OAuth로그인 콜백", description = "OAuth로그인 콜백", hidden = true)
    @GetMapping("/code/{registrationId}")
    public ResponseToken googleLogin(@RequestParam String code, @PathVariable String registrationId) {
        return authService.socialLogin(code, registrationId);
    }
}