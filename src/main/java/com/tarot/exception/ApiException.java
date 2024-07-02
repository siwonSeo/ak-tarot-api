package com.tarot.exception;

import com.tarot.code.ErrorStatusMessage;
import lombok.Getter;

@Getter
public class ApiException extends RuntimeException {
    private ErrorStatusMessage error;
    private String message;

    public ApiException(ErrorStatusMessage e) {
        this(e,e.getMessage());
    }

    public ApiException(ErrorStatusMessage e, String message) {
        super(message);
        this.error = e;
        this.message = message;
    }

}