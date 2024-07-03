package com.tarot.auth.controller;

import com.tarot.auth.dto.response.LoginResponse;
import com.tarot.common.config.DisableSwaggerSecurity;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.*;


@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@RestController
//@CrossOrigin(origins = {"http://localhost:8080", "http://localhost:3000"}, allowCredentials = "true")
public class AuthApiController {
//  private final RsaService rsaService;
//  private final AuthService authService;
  private final ClientRegistrationRepository clientRegistrationRepository;

//  @Operation(security = { @SecurityRequirement(name = "google_auth") })
  @DisableSwaggerSecurity
  @GetMapping("/authorize/{registrationId}")
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
    System.out.println(authorizationUri);
    log.debug(authorizationUri);
//    return ResponseEntity.status(HttpStatus.FOUND)
////            .location(URI.create(authorizationUri))
//            .location(URI.create(authorizationUri.replace(" ", "%20")))
//            .build();
      return ResponseEntity.ok("{\"authorizationUri\":\"" + authorizationUri + "\"}");
  }

  @GetMapping("/success")
  public ResponseEntity<LoginResponse> loginSuccess(@Valid LoginResponse loginResponse) {
    return ResponseEntity.ok(loginResponse);
  }
}
