package com.bkm.bkm_server.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class CipherResponse {
    private String serverDHPubKey;
    private String version;
}
