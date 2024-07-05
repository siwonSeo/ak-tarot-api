package com.tarot.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tarot.auth.dto.response.ResponseToken;
import com.tarot.common.constants.Constant;
import com.tarot.common.dto.CustomUserDetails;
import com.tarot.common.jwt.JwtTokenProvider;
import com.tarot.common.service.RedisService;
import com.tarot.user.entity.UserBase;
import com.tarot.user.repository.UserBaseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final Environment env;
    private final RestTemplate restTemplate;
    private final RedisService redisService;
    private final JwtTokenProvider jwtTokenProvider;

    private final UserBaseRepository userBaseRepository;

    @Value("${spring.data.redis.accessToken.validityInMinutes}")
    private long validityRedisInMinutes;

    @Value("${spring.data.redis.refreshToken.validityInHours}")
    private long validityRedisInHours;

    public ResponseToken socialLogin(String code, String registrationId) {
        log.info("======================================================");
        String token = getToken(code, registrationId);
        JsonNode userResourceNode = getUserResource(token, registrationId);

        System.out.println("userResourceNode:" + userResourceNode);
        log.info("userResourceNode = {}", userResourceNode);

        String email = userResourceNode.get("email").asText();
        String name = userResourceNode.get("name").asText();
        String picture = userResourceNode.get("picture").asText();

        UserBase user = userBaseRepository.findByEmail(email).orElseGet(
                ()-> userBaseRepository.save(new UserBase(email, name, picture))
        );

        Map<String, Object> attributes = new HashMap<>();
        userResourceNode.fields().forEachRemaining(entry -> attributes.put(entry.getKey(), entry.getValue().asText()));

        CustomUserDetails customUserDetails = new CustomUserDetails(
                user.getId(),
                "",
                user.getEmail(),
                user.getName(),
                user.getPicture(),
                Collections.emptyList());

        customUserDetails.setAttributes(attributes);
        customUserDetails.setAttributeKey("sub");

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                customUserDetails, null, customUserDetails.getAuthorities());
//        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtTokenProvider.createAccessToken(authentication);
        String refreshToken = jwtTokenProvider.createRefreshToken(authentication);

        redisService.setValue(Constant.REDIS_ACCESS_TOKEN_KEY+customUserDetails.getId(),accessToken,validityRedisInMinutes * 60 * 1000);
        redisService.setValue(Constant.REDIS_REFRESH_TOKEN_KEY+customUserDetails.getId(),refreshToken,validityRedisInHours * 60 * 60 * 1000);

        return new ResponseToken(
             accessToken
            ,refreshToken
            ,customUserDetails.getId()
            ,customUserDetails.getEmail()
            ,customUserDetails.getName()
            ,customUserDetails.getPicture()
        );
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

    private String getToken(String authorizationCode, String registrationId) {
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