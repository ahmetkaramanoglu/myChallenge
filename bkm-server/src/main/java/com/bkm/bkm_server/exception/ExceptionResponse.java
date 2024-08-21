package com.bkm.bkm_server.exception;

import com.bkm.bkm_server.response.Status;
import lombok.Data;

@Data
public class ExceptionResponse {
    private Status status;

    public ExceptionResponse(String errorCode, String errorMessage) {
        this.status = new Status(false, errorCode, errorMessage);
    }
}
