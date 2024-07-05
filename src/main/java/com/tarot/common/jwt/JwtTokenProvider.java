package com.tarot.common.jwt;

import com.tarot.common.code.ErrorStatusMessage;
import com.tarot.common.exception.ApiException;
import com.tarot.common.service.UserDetailsServiceImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {
    private final Key signingKey;
//    private final RedisTemplate<String, String> redisTemplate;
    private final UserDetailsServiceImpl userDetailsService;
    @Value("${jwt.accessToken.validityInMinutes}")
    private long validityInMinutes;

    @Value("${jwt.refreshToken.validityInHours}")
    private long validityInHours;
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey,
                            UserDetailsServiceImpl userDetailsService) {
        this.signingKey = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.userDetailsService = userDetailsService;
    }
    /**
     * Access 토큰 생성
     */
    public String createAccessToken(Authentication authentication) {
        log.info("createAccessToken authentication.getName():{}",authentication.getName());
        Claims claims = Jwts.claims().setSubject(authentication.getName());
        Date now = new Date();
        Date expireDate = new Date(System.currentTimeMillis() + validityInMinutes * 60 * 1000);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expireDate)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUserId(String token) {
        Jws<Claims> claims = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token);
        return claims.getBody().getSubject();
    }

    /**
     * Refresh 토큰 생성 및 레디스 저장
     */
    public String createRefreshToken(Authentication authentication) {
        Claims claims = Jwts.claims().setSubject(authentication.getName());
        Date now = new Date();
        Long REFRESH_TOKEN_VALIDITY = validityInHours * 60 * 60 * 1000;
        Date expireDate = new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY);

        String refreshToken = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expireDate)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();

//        // 레디스 저장
//        redisTemplate.opsForValue().set(
//                userDetails.getUsername(), refreshToken, REFRESH_TOKEN_VALIDITY, TimeUnit.MILLISECONDS);

        return refreshToken;
    }

    /**
     * 토큰으로부터 클레임을 만들고, 이를 통해 User 객체 생성해 Authentication 객체 반환
     */
    public Authentication getAuthentication(String token) {
        String userPrincipal = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        UserDetails userDetails = userDetailsService.loadUserByUsername(userPrincipal);

        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * http 헤더로부터 bearer 토큰을 가져옴.
     */
    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Access 토큰을 검증
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token");
            throw new ApiException(ErrorStatusMessage.TOKEN_EXPIRED);
        } catch (JwtException e) {
            log.error("Invalid JWT token");
            throw new ApiException(ErrorStatusMessage.UN_AUTHORIZED);
        }
    }

    /**
     * 만료된 access token 을 통해 레디스 서버에서 리프레쉬 토큰 검증 후 액세스 토큰 재발급
     */

    /*
    public String reissueAccessToken(String expiredAccessToken, String refreshToken) {
        // 입력된 리프레쉬 토큰 검증
        verifyToken(refreshToken);

        // 만료된 access token에서 username 추출
        String username = getUsernameFromExpiredToken(expiredAccessToken);

        // 레디스에서 username을 키로 가지는 refresh token 조회
        String savedRefreshToken = redisTemplate.opsForValue().get(username);

        // 클라이언트가 보낸 refresh token과 레디스에 저장된 refresh token 비교
        if (savedRefreshToken != null && savedRefreshToken.equals(refreshToken)) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
            String newAccessToken = createAccessToken(userDetails);
            return newAccessToken;
        } else {
            // 유효하지 않은 refresh token
            throw new ApiException(ErrorStatusMessage.UN_AUTHORIZED);
        }
    }

     */

    /**
     * 사용자 id 통해 레디스 서버에서 리프레쉬 토큰 검증 후 액세스 토큰 재발급
     */

    /*
    public String reissueAccessTokenById(String id, String refreshToken) {

        // 레디스에서 username을 키로 가지는 refresh token 조회
        String savedRefreshToken = redisTemplate.opsForValue().get(id);

        // 클라이언트가 보낸 refresh token과 레디스에 저장된 refresh token 비교
        if (savedRefreshToken != null && savedRefreshToken.equals(refreshToken)) {
            // refresh token이 유효하면 새로운 access token 발급
            UserDetails userDetails = userDetailsService.loadUserByUsername(id);
//            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, "",userDetails.getAuthorities());
            String newAccessToken = createAccessToken(userDetails);

            return newAccessToken;
        } else {
            // 유효하지 않은 refresh token
            throw new ApiException(ErrorStatusMessage.UN_AUTHORIZED);
        }
    }

     */

    /**
     * 만료된 access token 을 통해 레디스 서버에서 리프레쉬 토큰을 조회 및 만료 여부 검증
     */
    /*
    public boolean validateRefreshToken(String expiredAccessToken) {
        try {
            // 만료된 access token에서 username 추출
            String username = getUsernameFromExpiredToken(expiredAccessToken);

            // 레디스에서 username을 키로 가지는 refresh token 조회
            String refreshToken = redisTemplate.opsForValue().get(username);

            if (refreshToken != null) {
                // refresh token 유효성 검사
                try {
                    Jwts.parserBuilder()
                            .setSigningKey(signingKey)
                            .build()
                            .parseClaimsJws(refreshToken);
                    return true;
                } catch (ExpiredJwtException e) {
                    // 만료된 refresh token 레디스에서 삭제
                    redisTemplate.delete(username);
                    log.error("Expired refresh token");
                    return false;
                } catch (io.jsonwebtoken.JwtException e) {
                    log.error("Invalid refresh token");
                    return false;
                }
            } else {
                // refresh token 없음
                log.error("Refresh token not found");
                return false;
            }
        } catch (Exception e) {
            // 유효하지 않은 access token
            log.error("Invalid access token");
            return false;
        }
    }

     */

    /**
     * 만료된 access token에서 username 추출
     */
    private String getUsernameFromExpiredToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            return e.getClaims().getSubject();
        } catch (io.jsonwebtoken.JwtException e) {
            throw new ApiException(ErrorStatusMessage.UN_AUTHORIZED);
        }
    }

    /**
     * 토큰 검증
     */
    private Jws<Claims> verifyToken(String token)
            throws io.jsonwebtoken.security.SecurityException, MalformedJwtException,
            UnsupportedJwtException, IllegalArgumentException, ExpiredJwtException {
        return Jwts.parserBuilder()
                .setSigningKey(
                        signingKey)
                .build()
                .parseClaimsJws(token);
    }

    /**
     * access 토큰 레디스 블랙리스트 추가 및 refresh 토큰 삭제
     * 만료된 access 토큰의 경우 블랙리스트에 추가하지 않고 refresh 토큰만 삭제
     */
//    public void addToBlacklist(String accessToken) {
//        try {
//            // 액세스 토큰에서 만료 시간 추출
//            Date expirationDate = Jwts.parserBuilder()
//                    .setSigningKey(signingKey)
//                    .build()
//                    .parseClaimsJws(accessToken)
//                    .getBody()
//                    .getExpiration();
//
//            // 액세스 토큰에서 subject(사용자 ID) 추출
//            String subject = Jwts.parserBuilder()
//                    .setSigningKey(signingKey)
//                    .build()
//                    .parseClaimsJws(accessToken)
//                    .getBody()
//                    .getSubject();
//
//            // 액세스 토큰이 만료되지 않은 경우에만 블랙리스트에 추가
//            if (expirationDate.after(new Date())) {
//                // 액세스 토큰을 키로, 만료 시간을 값으로 하여 레디스에 저장
//                redisTemplate.opsForValue().set(accessToken, "blacklisted",
//                        expirationDate.getTime() - System.currentTimeMillis(),
//                        TimeUnit.MILLISECONDS);
//            }
//
//            // 사용자 ID를 키로 하여 레디스에서 리프레시 토큰 삭제
//            redisTemplate.delete(subject);
//        } catch (ExpiredJwtException e) {
//            // 만료된 액세스 토큰에서 subject(사용자 ID) 추출
//            String subject = e.getClaims().getSubject();
//
//            // 사용자 ID를 키로 하여 레디스에서 리프레시 토큰 삭제
//            redisTemplate.delete(subject);
//        } catch (JwtException e) {
//            log.error("Invalid access token");
//            throw new ApiException(ErrorStatusMessage.UN_AUTHORIZED);
//        }
//    }
}