package com.tarot.common.config;

import com.tarot.auth.handler.OAuth2FailureHandler;
import com.tarot.auth.handler.OAuth2SuccessHandler;
import com.tarot.auth.service.AuthService;
import com.tarot.auth.service.CustomOAuth2UserService;
import com.tarot.common.filter.JwtAuthenticationFilter;
import com.tarot.common.handler.CustomOAuth2AuthenticationFailureHandler;
import com.tarot.common.handler.CustomOAuth2AuthenticationSuccessHandler;
import com.tarot.common.jwt.JwtTokenProvider;
import com.tarot.user.repository.UserBaseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
            , "/login/**"
            , "/login/oauth2/code/**"
//            , "/login/oauth2/**"
            , "/oauth2/**"
            , "/css/**"
            , "/js/**"
            , "/img/**"
            , "/favicon.ico"
            , "/error"
    };

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthService authService;

    //    @Autowired
    private final UserBaseRepository userBaseRepository;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
//                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .headers(c -> c.frameOptions(
                        HeadersConfigurer.FrameOptionsConfig::disable).disable())
                .sessionManagement(c ->
                        c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(PERMIT_URLS).permitAll()
                        .anyRequest().authenticated()
                ).addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(a->a.baseUri("/api/auth/oauth2/authorize"))
//                        .redirectionEndpoint(r->r.baseUri("/api/auth/oauth2/callback/*"))
                        .redirectionEndpoint(r->r.baseUri("/login/oauth2/code/*"))
                        .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig.userService(customOAuth2UserService))
                        .successHandler(oAuth2SuccessHandler)
                        .failureHandler(new OAuth2FailureHandler())
                )
//                .exceptionHandling(e -> e
//                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
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

//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//
//        configuration.addAllowedOriginPattern("*");
//        configuration.addAllowedHeader("*");
//        configuration.addAllowedMethod("*");
//        configuration.setAllowCredentials(true);
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }
}