package com.tarot.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RequestMapping("/auth/api")
@RestController
public class AuthApiController {

    @GetMapping("/login")
    public String login(Model model) {
        return "login";
    }

    @GetMapping("/user")
    public String getUser(@AuthenticationPrincipal OAuth2User principal) {
        return "Hello, " + principal.getAttribute("name");
    }
}