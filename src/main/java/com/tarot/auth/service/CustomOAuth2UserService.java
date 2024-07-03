package com.tarot.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tarot.auth.dto.response.PrincipalDetails;
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
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final Environment env;
    private final RestTemplate restTemplate;
    private final RedisService redisService;
    private final JwtTokenProvider jwtTokenProvider;

    private final UserBaseRepository userBaseRepository;

    @Value("${spring.data.redis.accessToken.validityInMinutes}")
    private long validityRedisInMinutes;

    @Value("${spring.data.redis.refreshToken.validityInHours}")
    private long validityRedisInHours;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        log.info("======================================================");
        Map<String, Object> oAuth2UserAttributes = super.loadUser(userRequest).getAttributes();

        // 2. resistrationId 가져오기 (third-party id)
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // 3. userNameAttributeName 가져오기
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        // 4. 유저 정보 dto 생성
        log.info("oAuth2UserAttributes:{}",oAuth2UserAttributes);

        String email = oAuth2UserAttributes .get("email").toString();
        String name = oAuth2UserAttributes.get("name").toString();
        String picture = oAuth2UserAttributes.get("picture").toString();

        UserBase user = userBaseRepository.findByEmail(email).orElseGet(
                ()-> userBaseRepository.save(new UserBase(email, name, picture))
        );

        CustomUserDetails customUserDetails = new CustomUserDetails(
                user.getId(),
                "",
                user.getEmail(),
                user.getName(),
                user.getPicture(),
                Collections.emptyList());

//        Authentication authentication = new UsernamePasswordAuthenticationToken(
//                customUserDetails, null, customUserDetails.getAuthorities());
//        SecurityContextHolder.getContext().setAuthentication(authentication);

//        String accessToken = jwtTokenProvider.createAccessToken(customUserDetails);
//        String refreshToken = jwtTokenProvider.createRefreshToken(customUserDetails);
//
//        redisService.setValue(Constant.REDIS_ACCESS_TOKEN_KEY+customUserDetails.getId(),accessToken,validityRedisInMinutes * 60 * 1000);
//        redisService.setValue(Constant.REDIS_REFRESH_TOKEN_KEY+customUserDetails.getId(),refreshToken,validityRedisInHours * 60 * 60 * 1000);

        return new PrincipalDetails(user, oAuth2UserAttributes, userNameAttributeName);
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

}
