package com.tarot.code;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;


@RequiredArgsConstructor
@Getter
public enum ErrorStatusMessage {

    INPUT_UNVALID_ERROR(HttpStatus.BAD_REQUEST, "입력값이 불충분합니다."),
    UN_AUTHORIZED(HttpStatus.UNAUTHORIZED, "권한 불충분"),
    TOKEN_EXPIRED(HttpStatus.FORBIDDEN, "토큰 만료"),
    FORBIDDEN_USER(HttpStatus.FORBIDDEN, ""),
    INTERNAL_SERVER(HttpStatus.INTERNAL_SERVER_ERROR, "알수없는 오류가 발생했습니다.");


    private final HttpStatus httpStatus;
    private final String message;

}