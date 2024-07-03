package com.tarot.common.filter;

import com.tarot.common.jwt.JwtTokenProvider;
import com.tarot.common.code.ErrorStatusMessage;
import com.tarot.common.exception.ApiException;
import com.tarot.common.service.RedisService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final String[] excludeUrls = {"/user","/api/user"};
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            String token = jwtTokenProvider.resolveToken(request);


            if (token != null && jwtTokenProvider.validateToken(token)) {
                String id = jwtTokenProvider.getUserId(token);
                if(id != null && token.equals(redisService.getValue(id))){
                    Authentication auth = jwtTokenProvider.getAuthentication(token);
                    SecurityContextHolder.getContext().setAuthentication(auth); // 정상 토큰이면 SecurityContext에 저장
                }else{
                    log.info("레디스 토큰값");
                    throw new Exception("레디스 토큰확인");
                }
            }else{
                log.info("토큰 만료됨!!!!!!!!!!");
                throw new Exception("토큰만료");
            }

            filterChain.doFilter(request, response);
        } catch (RedisConnectionFailureException e) {
            SecurityContextHolder.clearContext();
            throw new ApiException(ErrorStatusMessage.INTERNAL_SERVER);
        } catch (Exception e) {
            throw new ApiException(ErrorStatusMessage.INTERNAL_SERVER);
        }

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return !Arrays.stream(excludeUrls).anyMatch(path::startsWith);
    }
}
