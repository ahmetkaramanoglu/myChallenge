package com.bkm.bkm_server.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class EncryptResponse {
    private String decryptData;
}
