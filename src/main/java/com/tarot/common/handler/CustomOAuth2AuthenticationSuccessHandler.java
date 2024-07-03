package com.tarot.common.handler;

import com.tarot.common.jwt.JwtTokenProvider;
import com.tarot.common.dto.CustomUserDetails;
import com.tarot.user.entity.UserBase;
import com.tarot.user.repository.UserBaseRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;

@Slf4j
@RequiredArgsConstructor
@Component
public class CustomOAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

//    @Autowired
    private final JwtTokenProvider jwtTokenProvider;

//    @Autowired
    private final UserBaseRepository userBaseRepository;

    @Value("${server.servlet.session.timeout}")
    private int TIMEOUT_SECOND;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("given_name");
        String picture = oAuth2User.getAttribute("picture");

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
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(
                "{\"token\":\"" + token + "\"}"
        );
    }
}