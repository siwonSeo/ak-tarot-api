package com.tarot.auth.dto.response;

public record ResponseToken(
         String accessToken
        ,String refreshToken
        ,Integer id
        ,String email
        ,String name
        ,String picture
    ) {
}
