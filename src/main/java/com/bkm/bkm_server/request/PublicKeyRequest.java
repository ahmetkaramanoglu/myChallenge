package com.bkm.bkm_server.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PublicKeyRequest {
    private String encryptedJWE;
    private String rsaPubKey;
}


