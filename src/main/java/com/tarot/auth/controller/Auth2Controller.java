package com.tarot.auth.controller;

import com.tarot.config.DisableSwaggerSecurity;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;


@RequiredArgsConstructor
@RequestMapping("/api/auth")
@RestController
public class Auth2Controller {
//  private final RsaService rsaService;
//  private final AuthService authService;
  private ClientRegistrationRepository clientRegistrationRepository;
  @DisableSwaggerSecurity
  @GetMapping("/oauth2/authorize/{registrationId}")
  public ResponseEntity<?> getAuthorizationUrl(@PathVariable String registrationId) {
    ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
    if (clientRegistration == null) {
      return ResponseEntity.badRequest().body("Unknown client registration id");
    }

    String authorizationUri = clientRegistration.getProviderDetails().getAuthorizationUri()
            + "?client_id=" + clientRegistration.getClientId()
            + "&response_type=code"
            + "&redirect_uri=" + clientRegistration.getRedirectUri()
            + "&scope=" + String.join(" ", clientRegistration.getScopes());

    return ResponseEntity.ok(Collections.singletonMap("authorizationUrl", authorizationUri));
  }

}
