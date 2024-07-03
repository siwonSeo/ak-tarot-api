package com.tarot.common.exception;

import lombok.Builder;
import lombok.Getter;

@Getter
public class ApiExceptionEntity {
    private String errorMessage;

    @Builder
    public ApiExceptionEntity(String errorMessage){
        this.errorMessage = errorMessage;
    }
}