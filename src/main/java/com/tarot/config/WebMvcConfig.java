package com.tarot.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
//
//    private static final String CORS_URL_PATTERN = "/**";
//    private static final String CORS_URL = "*";
//    private static final String CORS_METHOD = "*";
//
//    @Override
//    public void addCorsMappings(CorsRegistry registry) {
//        registry.addMapping(CORS_URL_PATTERN)
//                .allowedOrigins(CORS_URL)
//                .allowedMethods(CORS_METHOD);
//    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:8080", "http://localhost:3000", "https://accounts.google.com", "https://oauth2.googleapis.com")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);
     }


}
