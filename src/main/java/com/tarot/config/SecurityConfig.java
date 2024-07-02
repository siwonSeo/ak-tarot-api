package com.tarot.config;

import com.tarot.auth.*;
import com.tarot.repository.UserBaseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final String[] PERMIT_URLS = {
            "/"
            , "/card/**"
            , "/api/auth/**"
            , "/api/card/**"
            , "/tarot/**"
            , "/swagger-ui.html"
            , "/swagger-ui/**"
            , "/v3/api-docs/**"
            , "/auth/**"
            , "/oauth2/**"
            , "/css/**"
            , "/js/**"
            , "/img/**"
            , "/favicon.ico"
    };

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtTokenProvider jwtTokenProvider;

    //    @Autowired
    private final UserBaseRepository userBaseRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(PERMIT_URLS).permitAll()
                        .anyRequest().authenticated()
                ).addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/api/auth/login")
                        .authorizationEndpoint(authorization -> authorization
                                .baseUri("/api/auth/oauth2/authorize"))
                        .redirectionEndpoint(redirection -> redirection
                                .baseUri("/api/auth/oauth2/callback/*"))
                        .successHandler(oAuth2AuthenticationSuccessHandler())
                        .failureHandler(oAuth2AuthenticationFailureHandler())
                )
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable);
        ;
        return http.build();
    }

//    @Bean
//    public OAuth2UserService<OAuth2UserRequest, OAuth2User> customOAuth2UserService() {
//        return new CustomOAuth2UserService();
//    }

    @Bean
    public AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new CustomOAuth2AuthenticationSuccessHandler(jwtTokenProvider, userBaseRepository);
    }

    @Bean
    public AuthenticationFailureHandler oAuth2AuthenticationFailureHandler() {
        return new CustomOAuth2AuthenticationFailureHandler();
    }
    /*
    @Bean
    public CustomOAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new CustomOAuth2AuthenticationSuccessHandler();
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new CustomLogoutSuccessHandler();
    }

     */

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}