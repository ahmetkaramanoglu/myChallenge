package com.bkm.bkm_server.exception;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SoftOtpException extends RuntimeException {

    private String errorCode;
    private String errorDescription;
    private String errorStackTrace;

    public SoftOtpException(String stackTrace) {
        this.errorCode = Error.GENERAL_ERROR.getErrorCode();
        this.errorDescription = Error.GENERAL_ERROR.getErrorDescription();
        this.errorStackTrace = stackTrace;
    }
}