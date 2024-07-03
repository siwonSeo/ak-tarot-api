package com.tarot.common.filter;

import com.tarot.common.cookie.CookieProvider;
import com.tarot.common.jwt.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

@Slf4j
//@Component
@Deprecated // 미사용
@RequiredArgsConstructor
public class SessionAuthenticationFilter extends OncePerRequestFilter {
    private final String[] excludeUrls = {"/user","/api/user"};
    private final JwtTokenProvider jwtTokenProvider;
    private final CookieProvider cookieProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            HttpSession httpSession = request.getSession(false);
            if(httpSession == null){
                throw new Exception("세션 만료");
            }
            filterChain.doFilter(request, response);
        }catch (Exception e){
            /*
            try {
                SecurityContextHolder.clearContext(); // 보안 컨텍스트 초기화
            }catch (Exception se){
                log.info("security Exception:{}",e.getMessage());
            }
            */

            HttpSession session = request.getSession(false);
            log.info("###session{}:",session);
            if (session != null) {
                session.invalidate();
            }

            // 현재 요청이 API 요청인지 확인
            if (isApiRequest(request)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Unauthorized: Invalid or missing token");
                return; // 필터 체인 중단
            } else {
                // 웹 페이지 요청의 경우 메인 페이지로 리다이렉트
                response.sendRedirect("/");
                return; // 필터 체인 중단
            }
        }

    }

    private String getJwtFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            log.info(Arrays.toString(cookies));
            for (Cookie cookie : cookies) {
                if ("jwt_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }

    private boolean isApiRequest(HttpServletRequest request) {
        // API 요청을 구분하는 로직 (예: URL 경로로 판단)
        return request.getRequestURI().startsWith("/api");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return !Arrays.stream(excludeUrls).anyMatch(path::startsWith);
    }
}
