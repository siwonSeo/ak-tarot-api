package com.tarot.auth.handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.tarot.auth.dto.response.ResponseToken;
import com.tarot.common.constants.Constant;
import com.tarot.common.dto.CustomUserDetails;
import com.tarot.common.jwt.JwtTokenProvider;
import com.tarot.common.service.RedisService;
import com.tarot.user.entity.UserBase;
import com.tarot.user.repository.UserBaseRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
@Slf4j
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;

    private final RedisService redisService;
    private final UserBaseRepository userBaseRepository;

    @Value("${spring.data.redis.accessToken.validityInMinutes}")
    private long validityRedisInMinutes;

    @Value("${spring.data.redis.refreshToken.validityInHours}")
    private long validityRedisInHours;

    private AuthenticationManager authenticationManager;

    public void setAuthenticationManager(AuthenticationManager authenticationManager){
        this.authenticationManager  =  authenticationManager;
    }

    private static final String URI = "/api/auth/success";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        log.info("소셜로그인 성공");
        log.info("소셜로그인 성공:{}",authentication);

        log.info("소셜로그인 성공:{}",authentication.getDetails());
        log.info("소셜로그인 성공:{}",authentication.getDetails().getClass());
        log.info("소셜로그인 성공:{}",authentication.getPrincipal());
        log.info("소셜로그인 성공:{}",authentication.getPrincipal().getClass());
        log.info("소셜로그인 성공:{}",authentication.getCredentials());
        log.info("소셜로그인 성공:{}",authentication.getCredentials().getClass());

        DefaultOidcUser defaultOidcUser = (DefaultOidcUser)authentication.getPrincipal();

//        OidcUserInfo oidcUserInfo = defaultOidcUser.getUserInfo().getName()
        log.info("소셜로그인 성공:{}",defaultOidcUser);
        log.info("소셜로그인 성공:{}",defaultOidcUser.getUserInfo());

        String email = defaultOidcUser.getEmail();
        String name = defaultOidcUser.getName();
        String picture = defaultOidcUser.getPicture();

        UserBase user = userBaseRepository.findByEmail(email).orElseGet(
                ()-> userBaseRepository.save(new UserBase(email, name, picture))
        );

        UserDetails customUserDetails = new CustomUserDetails(
                user.getId(),
                "",
                user.getEmail(),
                user.getName(),
                user.getPicture(),
                Collections.emptyList());
//                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

        Authentication customAuthentication = new UsernamePasswordAuthenticationToken(
                customUserDetails, null, customUserDetails.getAuthorities());

//        authenticationManager.authenticate(customAuthentication);

//        SecurityContextHolder.getContext().setAuthentication(customAuthentication);


//        SecurityContextHolder.getContext().setAuthentication(customAuthentication);

        log.info("customAuthentication.getName:{}",customAuthentication.getName());
        log.info("customAuthentication.getName:{}",customAuthentication.getName().getClass());
        log.info("customAuthentication.getName:{}",customAuthentication.getPrincipal());
        log.info("customAuthentication.getName:{}",customAuthentication.getPrincipal().getClass());

        String accessToken = jwtTokenProvider.createAccessToken(customAuthentication);
        String refreshToken = jwtTokenProvider.createRefreshToken(customAuthentication);

        redisService.setValue(Constant.REDIS_ACCESS_TOKEN_KEY+user.getId(),accessToken,validityRedisInMinutes * 60 * 1000);
        redisService.setValue(Constant.REDIS_REFRESH_TOKEN_KEY+user.getId(),refreshToken,validityRedisInHours * 60 * 60 * 1000);

//        return new ResponseToken(
//                accessToken
//                ,refreshToken
//                ,customUserDetails.getId()
//                ,customUserDetails.getEmail()
//                ,customUserDetails.getName()
//                ,customUserDetails.getPicture()
//        );

        String redirectUrl = UriComponentsBuilder.fromUriString(URI)
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshToken)
                .queryParam("id", user.getId())
                .queryParam("email", user.getEmail())
                .queryParam("refreshToken", user.getName())
                .queryParam("refreshToken", user.getPicture())
                .build().toUriString();

        response.sendRedirect(redirectUrl);


//        authenticationManager.authenticate()





/*

        String email = authentication.getPrincipal("email").asText();
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
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtTokenProvider.createAccessToken(authentication);
        String refreshToken = jwtTokenProvider.createRefreshToken(customUserDetails);

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


 */
    }
}
