package com.tarot.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.method.HandlerMethod;

import java.util.Arrays;
import java.util.Collections;

@Configuration
public class SwaggerConfig {
    @Autowired
    private Environment env;
    @Bean
    public OpenAPI openAPI() {
        SecurityScheme securityScheme = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")
                .in(SecurityScheme.In.HEADER).name("Authorization");
        SecurityRequirement securityRequirement = new SecurityRequirement().addList("bearerAuth");

        return new OpenAPI()
                .components(new Components().addSecuritySchemes("bearerAuth", securityScheme))
                .security(Arrays.asList(securityRequirement));
    }

    @Bean
    public OperationCustomizer customize() {
        return (Operation operation, HandlerMethod handlerMethod) -> {
            DisableSwaggerSecurity methodAnnotation =
                    handlerMethod.getMethodAnnotation(DisableSwaggerSecurity.class);
            if (methodAnnotation != null) {
                operation.setSecurity(Collections.emptyList());
            }
            return operation;
        };
    }
}