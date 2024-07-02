package com.tarot.login.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tarot.auth.CustomUserDetails;
import com.tarot.auth.JwtTokenProvider;
import com.tarot.entity.user.UserBase;
import com.tarot.repository.UserBaseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;

@Service
@Slf4j
@RequiredArgsConstructor
public class LoginService {

    private final Environment env;
    private final RestTemplate restTemplate;
    //    @Autowired
    private final JwtTokenProvider jwtTokenProvider;

    //    @Autowired
    private final UserBaseRepository userBaseRepository;

    @Value("${server.servlet.session.timeout}")
    private int TIMEOUT_SECOND;

    public String socialLogin(String code, String registrationId) {
        log.info("======================================================");
        String accessToken = getAccessToken(code, registrationId);
        JsonNode userResourceNode = getUserResource(accessToken, registrationId);

        System.out.println("userResourceNode:" + userResourceNode);
        log.info("userResourceNode = {}", userResourceNode);

        String email = userResourceNode.get("email").asText();
        String name = userResourceNode.get("name").asText();
        String picture = userResourceNode.get("picture").asText();

        UserBase user = userBaseRepository.findByEmail(email).orElseGet(
                ()-> userBaseRepository.save(new UserBase(email, name, picture))
        );

        UserDetails userDetails = new CustomUserDetails(
                user.getId(),
                "",
                user.getEmail(),
                user.getName(),
                user.getPicture(),
                Collections.emptyList());

        String token = jwtTokenProvider.createAccessToken(userDetails);
        return "{\"token\":\"" + token + "\"}";
//        switch (registrationId) {
//            case "google": {
//                userResource.setId(userResourceNode.get("id").asText());
//                userResource.setEmail(userResourceNode.get("email").asText());
//                userResource.setNickname(userResourceNode.get("name").asText());
//                break;
//            } case "kakao": {
//                userResource.setId(userResourceNode.get("id").asText());
//                userResource.setEmail(userResourceNode.get("kakao_account").get("email").asText());
//                userResource.setNickname(userResourceNode.get("kakao_account").get("profile").get("nickname").asText());
//                break;
//            } case "naver": {
//                userResource.setId(userResourceNode.get("response").get("id").asText());
//                userResource.setEmail(userResourceNode.get("response").get("email").asText());
//                userResource.setNickname(userResourceNode.get("response").get("nickname").asText());
//                break;
//            } default: {
//                throw new RuntimeException("UNSUPPORTED SOCIAL TYPE");
//            }
//        }
    }

    private String getAccessToken(String authorizationCode, String registrationId) {
        String clientId = env.getProperty("security.oauth2.client.registration." + registrationId + ".client-id");
        String clientSecret = env.getProperty("security.oauth2.client.registration." + registrationId + ".client-secret");
        String redirectUri = env.getProperty("security.oauth2.client.registration." + registrationId + ".redirect-uri");
        String tokenUri = env.getProperty("security.oauth2.client.registration." + registrationId + ".token-uri");

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", authorizationCode);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity entity = new HttpEntity(params, headers);

        ResponseEntity<JsonNode> responseNode = restTemplate.exchange(tokenUri, HttpMethod.POST, entity, JsonNode.class);
        JsonNode accessTokenNode = responseNode.getBody();
        return accessTokenNode.get("access_token").asText();
    }

    private JsonNode getUserResource(String accessToken, String registrationId) {
        String resourceUri = env.getProperty("security.oauth2.client.registration." + registrationId + ".resource-uri");

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity entity = new HttpEntity(headers);

        return restTemplate.exchange(resourceUri, HttpMethod.GET, entity, JsonNode.class).getBody();
    }
}