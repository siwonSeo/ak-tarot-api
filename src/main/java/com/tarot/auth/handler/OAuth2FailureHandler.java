package com.tarot.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

@Slf4j
public class OAuth2FailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
        log.error("OAuth2 login fail. {}", request.getServletContext());
        log.error("OAuth2 login fail. {}", request.getHeaderNames());
        log.error("OAuth2 login fail. {}", request.getRequestURI());
        log.error("OAuth2 login fail. {}", request.getUserPrincipal());
        log.error("OAuth2 login fail. {}", response.getHeaderNames());
        log.error("OAuth2 login fail. {}", exception.getMessage());
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "소셜 로그인에 실패하였습니다.");
    }
}
