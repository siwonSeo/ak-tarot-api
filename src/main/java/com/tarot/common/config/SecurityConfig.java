package com.tarot.common.config;

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
            , "/login/oauth2/**"
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
//                .oauth2Login(oauth2 -> oauth2
////                        .loginPage("/api/auth/login")
////                        .authorizationEndpoint(authorization -> authorization
////                                .baseUri("/api/auth/oauth2/authorize"))
////                        .redirectionEndpoint(redirection -> redirection
////                                .baseUri("/login/oauth2/callback/**"))
////                                .baseUri("/login/oauth2/code/*"))
////                                .userInfoEndpoint(userInfoEndpointConfig ->
////                                        userInfoEndpointConfig
////                                                .userService(oAuth2UserService)
////                                )
//                        .successHandler(oAuth2AuthenticationSuccessHandler())
//                        .failureHandler(oAuth2AuthenticationFailureHandler())
//                )
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable);

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