package com.bkm.bkm_server.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Status {
    private boolean success;
    private String errorCode;
    private String errorMessage;
}
