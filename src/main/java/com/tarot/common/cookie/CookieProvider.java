package com.tarot.common.cookie;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

@Component
public class CookieProvider {
    protected void setCookie(HttpServletResponse response, String token){
        // JWT 토큰을 쿠키에 저장
        Cookie cookie = new Cookie("jwt_token", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true); // HTTPS 사용시에만 활성화
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    protected void removeCookies(HttpServletResponse response){
        // JWT 토큰 제거
        Cookie cookie = new Cookie("jwt_token", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);
//
//        Cookie cookie2 = new Cookie("JSESSIONID", null);
//        cookie.setMaxAge(0);
//        cookie.setPath("/");
//        response.addCookie(cookie2);
    }
}
