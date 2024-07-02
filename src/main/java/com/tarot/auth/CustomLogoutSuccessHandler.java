package com.tarot.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {
    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private CookieProvider cookieProvider;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        log.info("#####logout{}",authentication);

//        cookieProvider.removeCookies(response); //쿠키사용 제거
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.clearContext();
        log.info("#####auth{}",auth);

        // OAuth2 클라이언트 정보 제거
        if (auth instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) auth;
            log.info("redirect###oauthToken:{}",oauthToken);
            authorizedClientService.removeAuthorizedClient(
                    oauthToken.getAuthorizedClientRegistrationId(),
                    oauthToken.getName()
            );
}
    }
}
